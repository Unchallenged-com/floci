package io.floci.aws.services.kms;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.aws.services.cloudtrail.CloudTrailLogWriter;
import io.floci.aws.testing.CloudTrailLogFiles;
import io.floci.aws.testing.CloudTrailRequests;
import io.floci.aws.testing.EnforcementFixtures;
import io.floci.aws.testing.EnforcementFixtures.UserCredentials;
import io.floci.aws.testing.IamEnforcementProfile;
import io.floci.aws.testing.PartitionCleanup;
import io.floci.aws.testing.RestAssuredJsonUtils;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.path.json.JsonPath;
import io.restassured.response.ValidatableResponse;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;

/**
 * KMS's calls reach a trail's log files as CloudTrail management events, cryptographic operations
 * included, with the key in {@code resources} and without plaintext, ciphertext or grant tokens.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class KmsCloudTrailIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    /** The record's timestamp format: "Aug 10, 2022, 10:38:27 PM". */
    private static final String RECORD_TIME = "[A-Z][a-z]{2} \\d{1,2}, \\d{4}, \\d{1,2}:\\d{2}:\\d{2} (AM|PM)";

    @TestHTTPResource("/")
    static URI baseUri;

    @Inject
    CloudTrailLogWriter writer;

    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void callsAreRecordedWithTheirKeysAndWithoutSecrets() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-kms-logs-" + suffix;
        startTrail(account, "ct-kms-" + suffix, logs);

        JsonNode metadata = MAPPER.readTree(kms(account, "CreateKey", "{\"Description\": \"key-" + suffix + "\"}")
                .statusCode(200).extract().asString()).path("KeyMetadata");
        String keyArn = metadata.path("Arn").asText();
        String keyId = metadata.path("KeyId").asText();
        kms(account, "CreateAlias", "{\"AliasName\": \"alias/ct-" + suffix + "\", \"TargetKeyId\": \"" + keyId + "\"}")
                .statusCode(200);
        String ciphertext = kms(account, "Encrypt", "{\"KeyId\": \"alias/ct-" + suffix
                + "\", \"Plaintext\": \"c2VjcmV0LXBsYWludGV4dA==\", \"EncryptionContext\": {\"Team\": \"" + suffix + "\"}}")
                .statusCode(200).extract().path("CiphertextBlob");
        kms(account, "Decrypt", "{\"CiphertextBlob\": \"" + ciphertext + "\", \"EncryptionContext\": {\"Team\": \""
                + suffix + "\"}}").statusCode(200);
        kms(account, "GenerateDataKey", "{\"KeyId\": \"" + keyId + "\", \"KeySpec\": \"AES_256\"}").statusCode(200);
        kms(account, "CreateGrant", "{\"KeyId\": \"" + keyId + "\", \"GranteePrincipal\": \"arn:aws:iam::" + account
                + ":root\", \"Operations\": [\"Decrypt\"]}").statusCode(200);
        kms(account, "UpdateAlias", "{\"AliasName\": \"alias/ct-" + suffix + "\", \"TargetKeyId\": \"" + keyId + "\"}")
                .statusCode(200);
        kms(account, "DeleteAlias", "{\"AliasName\": \"alias/ct-" + suffix + "\"}").statusCode(200);
        kms(account, "ListAliases", "{}").statusCode(200);
        kms(account, "DescribeKey", "{\"KeyId\": \"alias/missing-" + suffix + "\"}").statusCode(400);
        kms(account, "ScheduleKeyDeletion", "{\"KeyId\": \"" + keyId + "\", \"PendingWindowInDays\": 7}")
                .statusCode(200);

        List<JsonNode> records = kmsRecords(account, logs);
        assertThat(records.toString(), not(containsString("c2VjcmV0LXBsYWludGV4dA")));
        assertThat(records.toString(), not(containsString(ciphertext)));

        JsonNode created = only(records, "CreateKey");
        assertThat(created.path("eventSource").asText(), equalTo("kms.amazonaws.com"));
        assertThat(created.path("readOnly").asBoolean(), equalTo(false));
        assertThat(created.path("requestParameters").path("description").asText(), equalTo("key-" + suffix));
        JsonNode keyMetadata = created.path("responseElements").path("keyMetadata");
        assertThat(keyMetadata.path("arn").asText(), equalTo(keyArn));
        assertThat(keyMetadata.path("aWSAccountId").asText(), equalTo(account));
        assertThat(keyMetadata.path("creationDate").asText(), matchesPattern(RECORD_TIME));
        assertKey(created, keyArn);

        JsonNode alias = only(records, "CreateAlias");
        assertThat(alias.path("responseElements").path("keyId").asText(), equalTo(keyArn));
        assertThat(alias.path("resources").size(), equalTo(2));
        assertThat(alias.path("resources").get(1).path("ARN").asText(), endsWith(":alias/ct-" + suffix));

        for (String aliasCall : List.of("UpdateAlias", "DeleteAlias")) {
            JsonNode changed = only(records, aliasCall);
            assertThat(changed.path("responseElements").path("keyId").asText(), equalTo(keyArn));
            assertThat(changed.path("resources").size(), equalTo(2));
            assertThat(changed.path("resources").get(0).path("ARN").asText(), endsWith(":alias/ct-" + suffix));
            assertThat(changed.path("resources").get(1).path("ARN").asText(), equalTo(keyArn));
        }

        JsonNode encrypted = only(records, "Encrypt");
        assertThat(encrypted.path("readOnly").asBoolean(), equalTo(true));
        assertThat(encrypted.path("requestParameters").path("encryptionContext").path("Team").asText(),
                equalTo(suffix));
        assertThat(encrypted.path("requestParameters").has("plaintext"), equalTo(false));
        assertThat(encrypted.path("responseElements").isNull(), equalTo(true));
        assertKey(encrypted, keyArn);

        JsonNode decrypted = only(records, "Decrypt");
        assertThat(decrypted.path("readOnly").asBoolean(), equalTo(true));
        assertThat(decrypted.path("requestParameters").path("keyId").asText(), equalTo(keyArn));
        assertThat(decrypted.path("requestParameters").path("encryptionAlgorithm").asText(),
                equalTo("SYMMETRIC_DEFAULT"));
        assertThat(decrypted.path("requestParameters").has("ciphertextBlob"), equalTo(false));
        assertThat(decrypted.path("responseElements").isNull(), equalTo(true));
        assertKey(decrypted, keyArn);

        assertThat(only(records, "GenerateDataKey").path("readOnly").asBoolean(), equalTo(true));

        JsonNode grant = only(records, "CreateGrant");
        assertThat(grant.path("responseElements").path("grantId").asText(null), notNullValue());
        assertThat(grant.path("responseElements").path("keyId").asText(), equalTo(keyArn));
        assertThat(grant.path("responseElements").has("grantToken"), equalTo(false));

        JsonNode listed = only(records, "ListAliases");
        assertThat(listed.path("readOnly").asBoolean(), equalTo(true));
        assertThat(listed.path("resources").size(), equalTo(0));

        JsonNode missing = only(records, "DescribeKey");
        assertThat(missing.path("errorCode").asText(), equalTo("NotFoundException"));
        assertThat(missing.path("resources").size(), equalTo(0));

        JsonNode scheduled = only(records, "ScheduleKeyDeletion");
        assertThat(scheduled.path("requestParameters").path("pendingWindowInDays").asInt(), equalTo(7));
        assertThat(scheduled.path("responseElements").path("keyId").asText(), equalTo(keyArn));
        assertThat(scheduled.path("responseElements").path("deletionDate").asText(), matchesPattern(RECORD_TIME));
    }

    @Test
    void aCallIamEnforcementRefusesIsRecordedWithoutItsParameters() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-kms-logs-" + suffix;
        startTrail(account, "ct-kms-" + suffix, logs);
        String user = "ct-user-" + suffix;
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, baseUri.getPort(),
                auth(account, "iam"), user);

        JsonPath answer = kms(credentials.accessKeyId(), "CreateKey", "{\"Description\": \"refused\"}")
                .statusCode(400).extract().jsonPath();

        // AWS records a refusal as AccessDenied, with the message the refusal answered with.
        JsonNode refused = only(kmsRecords(account, logs), "CreateKey");
        assertThat(refused.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(refused.path("errorMessage").asText(), equalTo(answer.getString("message")));
        assertThat(refused.path("userIdentity").path("userName").asText(), equalTo(user));
        assertThat(refused.path("requestParameters").isNull(), equalTo(true));
        assertThat(refused.path("responseElements").isNull(), equalTo(true));
    }

    private static void assertKey(JsonNode record, String keyArn) {
        assertThat(record.path("resources").get(0).path("type").asText(), equalTo("AWS::KMS::Key"));
        assertThat(record.path("resources").get(0).path("ARN").asText(), equalTo(keyArn));
    }

    /** An account of its own, so that this test reads only its own records. */
    private static String account() {
        return "6611" + String.format("%08d", (int) (Math.random() * 100_000_000));
    }

    private void startTrail(String account, String trail, String bucket) {
        given().port(baseUri.getPort()).header("Authorization", auth(account, "s3"))
                .when().put("/" + bucket).then().statusCode(200);
        cleanup.register(() -> EnforcementFixtures.removeBucket(baseUri.getPort(), auth(account, "s3"), bucket));
        cloudTrail(account, "CreateTrail", "{\"Name\":\"" + trail + "\",\"S3BucketName\":\"" + bucket + "\"}");
        cleanup.register(() -> cloudTrail(account, "DeleteTrail", "{\"Name\":\"" + trail + "\"}"));
        cloudTrail(account, "StartLogging", "{\"Name\":\"" + trail + "\"}");
    }

    private static void cloudTrail(String account, String action, String body) {
        CloudTrailRequests.invokeCloudTrail(auth(account, "cloudtrail"), action, body).then().statusCode(200);
    }

    private ValidatableResponse kms(String accessKeyId, String action, String body) {
        return given().port(baseUri.getPort())
                .header("Authorization", auth(accessKeyId, REGION, "kms"))
                .header("X-Amz-Target", "TrentService." + action)
                .contentType("application/x-amz-json-1.1")
                .body(body)
                .when().post("/")
                .then();
    }

    /** The KMS records of {@code account}, read from the log files the writer delivers to {@code bucket}. */
    private List<JsonNode> kmsRecords(String account, String bucket) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(account, "s3")).stream()
                .filter(record -> "kms.amazonaws.com".equals(record.path("eventSource").asText()))
                .toList();
    }

    private static JsonNode only(List<JsonNode> records, String eventName) {
        List<JsonNode> found = records.stream()
                .filter(record -> eventName.equals(record.path("eventName").asText()))
                .toList();
        assertThat(eventName + " in " + records, found, hasSize(1));
        return found.getFirst();
    }
}
