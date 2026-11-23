package io.floci.aws.services.cloudwatch.logs;

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
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;

/**
 * The CloudWatch Logs calls CloudTrail lists reach a trail's log files as management events, and
 * the ones it leaves out, such as {@code PutLogEvents}, do not.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class LogsCloudTrailIntegrationTest {

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
    void listedCallsAreRecordedAndPutLogEventsIsNot() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-logs-logs-" + suffix;
        String group = "/ct/" + suffix;
        startTrail(account, "ct-logs-" + suffix, logs);

        logs(account, "CreateLogGroup", "{\"logGroupName\": \"" + group + "\", \"tags\": {\"Team\": \"ops\"}}")
                .statusCode(200);
        logs(account, "CreateLogStream", "{\"logGroupName\": \"" + group + "\", \"logStreamName\": \"s\"}")
                .statusCode(200);
        logs(account, "PutLogEvents", "{\"logGroupName\": \"" + group + "\", \"logStreamName\": \"s\", \"logEvents\": "
                + "[{\"timestamp\": " + System.currentTimeMillis() + ", \"message\": \"hello\"}]}").statusCode(200);
        logs(account, "GetLogEvents", "{\"logGroupName\": \"" + group + "\", \"logStreamName\": \"s\"}")
                .statusCode(200);
        logs(account, "PutRetentionPolicy", "{\"logGroupName\": \"" + group + "\", \"retentionInDays\": 1}")
                .statusCode(200);
        logs(account, "DeleteLogGroup", "{\"logGroupName\": \"" + group + "-missing\"}").statusCode(400);
        logs(account, "DeleteLogGroup", "{\"logGroupName\": \"" + group + "\"}").statusCode(200);

        List<JsonNode> records = logsRecords(account, logs);

        JsonNode created = only(records, "CreateLogGroup", false);
        assertThat(created.path("eventSource").asText(), equalTo("logs.amazonaws.com"));
        assertThat(created.path("apiVersion").asText(), equalTo("20140328"));
        assertThat(created.path("readOnly").asBoolean(), equalTo(false));
        assertThat(created.path("requestParameters").path("logGroupName").asText(), equalTo(group));
        assertThat(created.path("requestParameters").path("tags").path("Team").asText(), equalTo("ops"));
        assertThat(created.path("responseElements").isNull(), equalTo(true));

        JsonNode read = only(records, "GetLogEvents", false);
        assertThat(read.path("readOnly").asBoolean(), equalTo(true));
        assertThat(read.path("responseElements").isNull(), equalTo(true));

        JsonNode retention = only(records, "PutRetentionPolicy", false);
        assertThat(retention.path("requestParameters").path("retentionInDays").asInt(), equalTo(1));

        JsonNode missing = only(records, "DeleteLogGroup", true);
        assertThat(missing.path("errorCode").asText(), equalTo("ResourceNotFoundException"));
        assertThat(missing.path("errorMessage").asText(), not(emptyOrNullString()));
        assertThat(only(records, "DeleteLogGroup", false).path("requestParameters").path("logGroupName").asText(),
                equalTo(group));

        assertThat(records.stream().filter(r -> "PutLogEvents".equals(r.path("eventName").asText())).toList(),
                hasSize(0));
    }

    @Test
    void aCallIamEnforcementRefusesIsRecordedWithoutItsParameters() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-logs-logs-" + suffix;
        startTrail(account, "ct-logs-" + suffix, logs);
        String user = "ct-user-" + suffix;
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, baseUri.getPort(),
                auth(account, "iam"), user);

        JsonPath answer = logs(credentials.accessKeyId(), "DeleteLogGroup",
                "{\"logGroupName\": \"/ct/" + suffix + "\"}").statusCode(400).extract().jsonPath();

        // AWS records a refusal as AccessDenied, with the message the refusal answered with.
        JsonNode refused = only(logsRecords(account, logs), "DeleteLogGroup", true);
        assertThat(refused.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(refused.path("errorMessage").asText(), equalTo(answer.getString("message")));
        assertThat(refused.path("userIdentity").path("userName").asText(), equalTo(user));
        assertThat(refused.path("requestParameters").isNull(), equalTo(true));
    }

    /** An account of its own, so that this test reads only its own records. */
    private static String account() {
        return "6612" + String.format("%08d", (int) (Math.random() * 100_000_000));
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

    private ValidatableResponse logs(String accessKeyId, String action, String body) {
        return given().port(baseUri.getPort())
                .header("Authorization", auth(accessKeyId, REGION, "logs"))
                .header("X-Amz-Target", "Logs_20140328." + action)
                .contentType("application/x-amz-json-1.1")
                .body(body)
                .when().post("/")
                .then();
    }

    /** The CloudWatch Logs records of {@code account}, read from the log files delivered to {@code bucket}. */
    private List<JsonNode> logsRecords(String account, String bucket) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(account, "s3")).stream()
                .filter(record -> "logs.amazonaws.com".equals(record.path("eventSource").asText()))
                .toList();
    }

    private static JsonNode only(List<JsonNode> records, String eventName, boolean failed) {
        List<JsonNode> found = records.stream()
                .filter(record -> eventName.equals(record.path("eventName").asText()))
                .filter(record -> record.has("errorCode") == failed)
                .toList();
        assertThat(eventName + " in " + records, found, hasSize(1));
        return found.getFirst();
    }
}
