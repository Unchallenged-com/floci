package io.floci.aws.services.account;

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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;

/**
 * Account Management calls reach a trail's log files as management events recorded in us-east-1, whatever Region
 * the caller signed for, with their members but never the values they return.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class AccountCloudTrailIntegrationTest {

    private static final String CALLER_REGION = "eu-west-1";
    private static final String RECORDED_REGION = "us-east-1";
    private static final String PHONE = "+1 555 0" + (int) (Math.random() * 900 + 100);
    private static final String ADDRESS = "do-not-log-" + UUID.randomUUID();

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
    void callsAreRecordedInUsEast1WithoutTheirAnswers() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-account-logs-" + suffix;
        String regional = "ct-account-regional-" + suffix;
        startTrail(account, "ct-account-" + suffix, logs, true);
        startTrail(account, "ct-account-regional-" + suffix, regional, false);

        account(account, "/putAlternateContact", "{\"AlternateContactType\":\"SECURITY\",\"Name\":\"Sec Team\","
                + "\"Title\":\"CISO\",\"EmailAddress\":\"sec@example.com\",\"PhoneNumber\":\"" + PHONE + "\"}")
                .statusCode(200);
        cleanup.register(() -> account(account, "/deleteAlternateContact", "{\"AlternateContactType\":\"SECURITY\"}"));
        account(account, "/getAlternateContact", "{\"AlternateContactType\":\"SECURITY\"}").statusCode(200);
        account(account, "/deleteAlternateContact", "{\"AlternateContactType\":\"SECURITY\"}").statusCode(200);
        account(account, "/getAlternateContact", "{\"AlternateContactType\":\"SECURITY\"}").statusCode(404);
        account(account, "/putContactInformation", "{\"ContactInformation\":{\"FullName\":\"Ops\","
                + "\"AddressLine1\":\"" + ADDRESS + "\",\"City\":\"Seattle\",\"StateOrRegion\":\"WA\",\"PostalCode\":\"98101\","
                + "\"CountryCode\":\"US\",\"PhoneNumber\":\"" + PHONE + "\"}}").statusCode(200);
        account(account, "/getContactInformation", "{}").statusCode(200);
        account(account, "/putAccountName", "{\"AccountName\":\"ct-renamed\"}").statusCode(200);
        account(account, "/getAccountInformation", "{}").statusCode(200);

        List<JsonNode> records = accountRecords(account, logs);
        assertThat(records.toString(), not(containsString(PHONE)));
        assertThat(records.toString(), not(containsString(ADDRESS)));
        assertThat(records.toString(), not(containsString("ct-renamed")));
        for (JsonNode record : records) {
            assertThat(record.toString(), record.path("awsRegion").asText(), equalTo(RECORDED_REGION));
            assertThat(record.path("responseElements").isNull(), equalTo(true));
            assertThat(record.path("recipientAccountId").asText(), equalTo(account));
        }
        assertThat(accountRecords(account, regional), empty());

        JsonNode put = only(records, "PutAlternateContact");
        assertThat(put.path("eventSource").asText(), equalTo("account.amazonaws.com"));
        assertThat(put.path("readOnly").asBoolean(true), equalTo(false));
        JsonNode contact = put.path("requestParameters");
        assertThat(contact.path("alternateContactType").asText(), equalTo("SECURITY"));
        assertThat(contact.path("name").asText(), equalTo("Sec Team"));
        assertThat(contact.path("title").asText(), equalTo("CISO"));
        assertThat(contact.path("emailAddress").asText(), equalTo("sec@example.com"));
        assertThat(contact.has("phoneNumber"), equalTo(false));

        List<JsonNode> reads = named(records, "GetAlternateContact");
        assertThat(reads, hasSize(2));
        JsonNode read = reads.stream().filter(record -> !record.has("errorCode")).findFirst().orElseThrow();
        assertThat(read.path("readOnly").asBoolean(), equalTo(true));
        assertThat(read.path("requestParameters").path("alternateContactType").asText(), equalTo("SECURITY"));
        JsonNode missing = reads.stream().filter(record -> record.has("errorCode")).findFirst().orElseThrow();
        assertThat(missing.path("errorCode").asText(), equalTo("ResourceNotFoundException"));
        assertThat(missing.path("requestParameters").path("alternateContactType").asText(), equalTo("SECURITY"));

        JsonNode deleted = only(records, "DeleteAlternateContact");
        assertThat(deleted.path("readOnly").asBoolean(true), equalTo(false));
        assertThat(deleted.path("requestParameters").path("alternateContactType").asText(), equalTo("SECURITY"));

        assertThat(only(records, "PutContactInformation").path("readOnly").asBoolean(true), equalTo(false));
        assertThat(only(records, "GetContactInformation").path("readOnly").asBoolean(), equalTo(true));
        assertThat(only(records, "PutAccountName").path("readOnly").asBoolean(true), equalTo(false));
        assertThat(only(records, "GetAccountInformation").path("readOnly").asBoolean(), equalTo(true));
    }

    @Test
    void aRefusedCallIsRecordedWithoutItsMembers() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-account-refused-" + suffix;
        startTrail(account, "ct-account-refused-" + suffix, logs, true);
        String user = "ct-user-" + suffix;
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, baseUri.getPort(),
                auth(account, "iam"), user);

        account(credentials.accessKeyId(), "/putAlternateContact", "{\"AlternateContactType\":\"SECURITY\","
                + "\"Name\":\"Mallory\",\"Title\":\"x\",\"EmailAddress\":\"m@example.com\",\"PhoneNumber\":\""
                + PHONE + "\"}").statusCode(403);

        JsonNode refused = only(accountRecords(account, logs), "PutAlternateContact");
        assertThat(refused.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(refused.path("errorMessage").asText(), containsString("account:PutAlternateContact"));
        assertThat(refused.path("awsRegion").asText(), equalTo(RECORDED_REGION));
        assertThat(refused.path("userIdentity").path("userName").asText(), equalTo(user));
        assertThat(refused.path("requestParameters").isNull(), equalTo(true));
        assertThat(refused.path("responseElements").isNull(), equalTo(true));
    }

    private static ValidatableResponse account(String caller, String path, String body) {
        return given().contentType("application/json")
                .header("Authorization", auth(caller, CALLER_REGION, "account"))
                .body(body).post(path).then();
    }

    private static String account() {
        return "6616" + String.format("%08d", (int) (Math.random() * 100_000_000));
    }

    private void startTrail(String account, String trail, String bucket, boolean globalServiceEvents) {
        given().port(baseUri.getPort()).header("Authorization", auth(account, "s3"))
                .when().put("/" + bucket).then().statusCode(200);
        cleanup.register(() -> EnforcementFixtures.removeBucket(baseUri.getPort(), auth(account, "s3"), bucket));
        cloudTrail(account, "CreateTrail", "{\"Name\":\"" + trail + "\",\"S3BucketName\":\"" + bucket
                + "\",\"IncludeGlobalServiceEvents\":" + globalServiceEvents + "}");
        cleanup.register(() -> cloudTrail(account, "DeleteTrail", "{\"Name\":\"" + trail + "\"}"));
        cloudTrail(account, "StartLogging", "{\"Name\":\"" + trail + "\"}");
    }

    private static void cloudTrail(String account, String action, String body) {
        CloudTrailRequests.invokeCloudTrail(auth(account, "cloudtrail"), action, body).then().statusCode(200);
    }

    /** The Account records of {@code account}, read from the log files delivered to {@code bucket}. */
    private List<JsonNode> accountRecords(String account, String bucket) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(account, "s3")).stream()
                .filter(record -> "account.amazonaws.com".equals(record.path("eventSource").asText()))
                .toList();
    }

    private static List<JsonNode> named(List<JsonNode> records, String eventName) {
        return records.stream().filter(record -> eventName.equals(record.path("eventName").asText())).toList();
    }

    private static JsonNode only(List<JsonNode> records, String eventName) {
        List<JsonNode> found = named(records, eventName);
        assertThat(eventName + " in " + records, found, hasSize(1));
        return found.getFirst();
    }
}
