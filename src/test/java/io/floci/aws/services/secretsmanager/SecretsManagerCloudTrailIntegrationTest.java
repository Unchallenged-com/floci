package io.floci.aws.services.secretsmanager;

import com.fasterxml.jackson.databind.JsonNode;
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
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;

/**
 * Secrets Manager's calls reach a trail's log files as CloudTrail management events, whether
 * Secrets Manager ran them, refused them, or IAM enforcement refused them first, and no record
 * carries a secret's value.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class SecretsManagerCloudTrailIntegrationTest {

    private static final String ACCOUNT = "661100000643";
    private static final String REGION = "us-east-1";

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
    void callsAreRecordedAsManagementEventsWithoutSecretValues() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String name = "ct-secret-" + suffix;
        String logs = "ct-sm-logs-" + suffix;
        startTrail("ct-sm-" + suffix, logs);

        String arn = secrets(ACCOUNT, "CreateSecret", """
                {"Name": "%s", "SecretString": "value-%s", "Description": "db password",
                 "Tags": [{"Key": "Team", "Value": "%s"}]}""".formatted(name, suffix, suffix))
                .statusCode(200).extract().path("ARN");
        secrets(ACCOUNT, "GetSecretValue", "{\"SecretId\": \"" + name + "\"}").statusCode(200);
        secrets(ACCOUNT, "ListSecrets", """
                {"Filters": [{"Key": "tag-value", "Values": ["%s"]}], "MaxResults": 100}""".formatted(suffix))
                .statusCode(200);
        secrets(ACCOUNT, "BatchGetSecretValue", "{\"SecretIdList\": [\"" + arn + "\"]}").statusCode(200);
        secrets(ACCOUNT, "PutSecretValue", "{\"SecretId\": \"" + name + "\", \"SecretString\": \"next-" + suffix + "\"}")
                .statusCode(200);
        secrets(ACCOUNT, "DeleteSecret", "{\"SecretId\": \"" + name + "-missing\"}").statusCode(400);
        secrets(ACCOUNT, "DeleteSecret", "{\"SecretId\": \"" + name + "\", \"ForceDeleteWithoutRecovery\": true}")
                .statusCode(200);

        List<JsonNode> records = secretRecords(logs, suffix, suffix);
        assertThat(records.toString(), not(containsString("value-" + suffix)));
        assertThat(records.toString(), not(containsString("next-" + suffix)));
        assertThat(records.toString(), not(containsString("aRN")));

        JsonNode created = only(records, "CreateSecret");
        assertThat(created.path("eventSource").asText(), equalTo("secretsmanager.amazonaws.com"));
        assertThat(created.path("eventCategory").asText(), equalTo("Management"));
        assertThat(created.path("managementEvent").asBoolean(), equalTo(true));
        assertThat(created.path("readOnly").asBoolean(), equalTo(false));
        assertThat(created.path("awsRegion").asText(), equalTo(REGION));
        assertThat(created.path("sourceIPAddress").asText(), equalTo("127.0.0.1"));
        assertThat(created.path("requestParameters").path("name").asText(), equalTo(name));
        assertThat(created.path("requestParameters").path("tags").get(0).path("value").asText(), equalTo(suffix));
        assertThat(created.path("requestParameters").has("secretString"), equalTo(false));
        assertThat(created.path("responseElements").path("arn").asText(), equalTo(arn));
        assertThat(created.path("responseElements").path("name").asText(), equalTo(name));

        JsonNode read = only(records, "GetSecretValue");
        assertThat(read.path("readOnly").asBoolean(), equalTo(true));
        assertThat(read.path("requestParameters").path("secretId").asText(), equalTo(name));
        assertThat(read.path("responseElements").isNull(), equalTo(true));

        JsonNode listed = only(records, "ListSecrets");
        assertThat(listed.path("readOnly").asBoolean(), equalTo(true));
        assertThat(listed.path("requestParameters").path("maxResults").isInt(), equalTo(true));
        assertThat(listed.path("requestParameters").path("filters").get(0).path("key").asText(),
                equalTo("tag-value"));

        JsonNode batch = only(records, "BatchGetSecretValue");
        assertThat(batch.path("readOnly").asBoolean(), equalTo(true));
        assertThat(batch.path("responseElements").isNull(), equalTo(true));

        JsonNode put = only(records, "PutSecretValue");
        assertThat(put.path("requestParameters").path("secretId").asText(), equalTo(name));
        assertThat(put.path("requestParameters").has("secretString"), equalTo(false));
        assertThat(put.path("responseElements").path("arn").asText(), equalTo(arn));

        List<JsonNode> deletes = records.stream().filter(r -> "DeleteSecret".equals(r.path("eventName").asText()))
                .toList();
        assertThat(deletes, hasSize(2));
        JsonNode missing = deletes.stream().filter(r -> r.has("errorCode")).findFirst().orElseThrow();
        assertThat(missing.path("errorCode").asText(), equalTo("ResourceNotFoundException"));
        assertThat(missing.path("errorMessage").asText(), not(emptyOrNullString()));
        assertThat(missing.path("responseElements").isNull(), equalTo(true));
        JsonNode deleted = deletes.stream().filter(r -> !r.has("errorCode")).findFirst().orElseThrow();
        assertThat(deleted.path("requestParameters").path("forceDeleteWithoutRecovery").asBoolean(), equalTo(true));
        assertThat(deleted.path("responseElements").path("arn").asText(), equalTo(arn));
    }

    @Test
    void aCallIamEnforcementRefusesIsRecordedWithoutItsParameters() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-sm-logs-" + suffix;
        startTrail("ct-sm-" + suffix, logs);
        String user = "ct-user-" + suffix;
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, baseUri.getPort(),
                auth(ACCOUNT, "iam"), user);

        JsonPath answer = secrets(credentials.accessKeyId(), "GetSecretValue",
                "{\"SecretId\": \"ct-refused-" + suffix + "\"}").statusCode(400).extract().jsonPath();

        // AWS records a refusal as AccessDenied, with the message the refusal answered with.
        List<JsonNode> records = secretRecords(logs, suffix, user);
        JsonNode refused = only(records, "GetSecretValue");
        assertThat(refused.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(refused.path("errorMessage").asText(), equalTo(answer.getString("message")));
        assertThat(refused.path("errorMessage").asText(), containsString("secretsmanager:GetSecretValue"));
        assertThat(refused.path("userIdentity").path("userName").asText(), equalTo(user));
        assertThat(refused.path("requestParameters").isNull(), equalTo(true));
        assertThat(refused.path("responseElements").isNull(), equalTo(true));
    }

    private void startTrail(String trail, String bucket) {
        given().port(baseUri.getPort()).header("Authorization", auth(ACCOUNT, "s3"))
                .when().put("/" + bucket).then().statusCode(200);
        cleanup.register(() -> EnforcementFixtures.removeBucket(baseUri.getPort(), auth(ACCOUNT, "s3"), bucket));
        cloudTrail("CreateTrail", "{\"Name\":\"" + trail + "\",\"S3BucketName\":\"" + bucket + "\"}");
        cleanup.register(() -> cloudTrail("DeleteTrail", "{\"Name\":\"" + trail + "\"}"));
        cloudTrail("StartLogging", "{\"Name\":\"" + trail + "\"}");
    }

    private static void cloudTrail(String action, String body) {
        CloudTrailRequests.invokeCloudTrail(auth(ACCOUNT, "cloudtrail"), action, body).then().statusCode(200);
    }

    private ValidatableResponse secrets(String accessKeyId, String action, String body) {
        return given().port(baseUri.getPort())
                .header("Authorization", auth(accessKeyId, REGION, "secretsmanager"))
                .header("X-Amz-Target", "secretsmanager." + action)
                .contentType("application/x-amz-json-1.1")
                .body(body)
                .when().post("/")
                .then();
    }

    /**
     * The Secrets Manager records whose parameters, results or caller name {@code marker}, read from
     * the log files the writer delivers to {@code bucket}; {@code suffix} keeps them to this test's.
     */
    private List<JsonNode> secretRecords(String bucket, String suffix, String marker) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(ACCOUNT, "s3")).stream()
                .filter(record -> "secretsmanager.amazonaws.com".equals(record.path("eventSource").asText())
                        && record.toString().contains(suffix) && record.toString().contains(marker))
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
