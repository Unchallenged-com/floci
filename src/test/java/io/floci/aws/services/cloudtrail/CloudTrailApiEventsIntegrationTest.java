package io.floci.aws.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;

/**
 * CloudTrail's own API calls reach the trails that log management events, as any service's calls do,
 * and a trail whose logging is stopped receives no event that occurred afterwards.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class CloudTrailApiEventsIntegrationTest {

    private static final String ACCOUNT = "661100000291";

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
    void trailManagementCallsAreRecordedAsManagementEvents() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String audit = "ct-audit-" + suffix;
        String auditLogs = "ct-audit-logs-" + suffix;
        startTrail(audit, auditLogs);
        String main = "ct-main-" + suffix;
        String mainLogs = "ct-main-logs-" + suffix;
        startTrail(main, mainLogs);
        String doomed = "ct-doomed-" + suffix;
        createBucket("ct-doomed-logs-" + suffix);
        cloudTrail(ACCOUNT, "CreateTrail", "{\"Name\":\"" + doomed + "\",\"S3BucketName\":\"ct-doomed-logs-" + suffix
                + "\"}").statusCode(200);

        cloudTrail(ACCOUNT, "UpdateTrail", "{\"Name\":\"" + main + "\",\"EnableLogFileValidation\":true}")
                .statusCode(200);
        cloudTrail(ACCOUNT, "PutEventSelectors", "{\"TrailName\":\"" + main + "\",\"EventSelectors\":"
                + "[{\"ReadWriteType\":\"All\",\"IncludeManagementEvents\":true}]}").statusCode(200);
        cloudTrail(ACCOUNT, "GetTrailStatus", "{\"Name\":\"" + main + "\"}").statusCode(200);
        cloudTrail(ACCOUNT, "UpdateTrail", "{\"Name\":\"ct-missing-" + suffix + "\",\"IsMultiRegionTrail\":true}")
                .statusCode(400);
        cloudTrail(ACCOUNT, "StopLogging", "{\"Name\":\"" + main + "\"}").statusCode(200);
        cloudTrail(ACCOUNT, "DeleteTrail", "{\"Name\":\"" + doomed + "\"}").statusCode(200);
        cloudTrail(ACCOUNT, "GetTrailStatus", "{\"Name\":\"" + main + "\"}").statusCode(200);

        List<JsonNode> records = cloudTrailRecords(auditLogs, suffix);

        JsonNode created = only(records, "CreateTrail", main);
        assertThat(created.path("eventSource").asText(), equalTo("cloudtrail.amazonaws.com"));
        assertThat(created.path("eventCategory").asText(), equalTo("Management"));
        assertThat(created.path("readOnly").asBoolean(), equalTo(false));
        assertThat(created.path("awsRegion").asText(), equalTo("us-east-1"));
        assertThat(created.path("sourceIPAddress").asText(), equalTo("127.0.0.1"));
        assertThat(created.path("userAgent").asText(), not(emptyOrNullString()));
        assertThat(created.path("requestParameters").path("s3BucketName").asText(), equalTo(mainLogs));
        assertThat(created.path("responseElements").path("trailARN").asText(),
                equalTo("arn:aws:cloudtrail:us-east-1:" + ACCOUNT + ":trail/" + main));

        JsonNode started = only(records, "StartLogging", main);
        assertThat(started.path("requestParameters").path("name").asText(), equalTo(main));
        assertThat(started.path("responseElements").isNull(), equalTo(true));

        JsonNode updated = records.stream().filter(r -> "UpdateTrail".equals(r.path("eventName").asText())
                && !r.has("errorCode")).findFirst().orElseThrow();
        assertThat(updated.path("requestParameters").path("name").asText(), equalTo(main));
        assertThat(updated.path("requestParameters").path("enableLogFileValidation").isBoolean(), equalTo(true));
        assertThat(updated.path("responseElements").path("logFileValidationEnabled").asBoolean(), equalTo(true));

        JsonNode selectors = only(records, "PutEventSelectors", main);
        assertThat(selectors.path("requestParameters").path("trailName").asText(), equalTo(main));
        assertThat(selectors.path("requestParameters").path("eventSelectors").get(0).path("readWriteType").asText(),
                equalTo("All"));
        assertThat(selectors.path("responseElements").path("eventSelectors").get(0).path("readWriteType").asText(),
                equalTo("All"));

        List<JsonNode> statuses = byName(records, "GetTrailStatus");
        assertThat(statuses, hasSize(2));
        assertThat(statuses.getFirst().path("readOnly").asBoolean(), equalTo(true));
        assertThat(statuses.getFirst().path("responseElements").isNull(), equalTo(true));

        JsonNode missing = only(records, "UpdateTrail", "ct-missing-" + suffix);
        assertThat(missing.path("errorCode").asText(), equalTo("TrailNotFoundException"));
        assertThat(missing.path("errorMessage").asText(), not(emptyOrNullString()));
        assertThat(missing.path("requestParameters").path("isMultiRegionTrail").asBoolean(), equalTo(true));
        assertThat(missing.path("responseElements").isNull(), equalTo(true));

        JsonNode stopped = only(records, "StopLogging", main);
        assertThat(stopped.path("readOnly").asBoolean(), equalTo(false));
        assertThat(stopped.path("requestParameters").path("name").asText(), equalTo(main));
        assertThat(stopped.path("responseElements").isNull(), equalTo(true));

        JsonNode deleted = only(records, "DeleteTrail", doomed);
        assertThat(deleted.path("requestParameters").path("name").asText(), equalTo(doomed));
        assertThat(deleted.path("responseElements").isNull(), equalTo(true));

        List<JsonNode> ownRecords = cloudTrailRecords(mainLogs, suffix);
        assertThat(byName(ownRecords, "PutEventSelectors"), hasSize(1));
        assertThat("no event after StopLogging reaches the stopped trail",
                byName(ownRecords, "DeleteTrail"), empty());
        assertThat(byName(ownRecords, "GetTrailStatus"), hasSize(1));
    }

    @Test
    void aStopLoggingIamEnforcementRefusesIsRecordedAndLoggingGoesOn() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String trail = "ct-kept-" + suffix;
        String logs = "ct-kept-logs-" + suffix;
        startTrail(trail, logs);
        UserCredentials intruder = EnforcementFixtures.createUser(cleanup, baseUri.getPort(), auth(ACCOUNT, "iam"),
                "ct-intruder-" + suffix);

        cloudTrail(intruder.accessKeyId(), "StopLogging", "{\"Name\":\"" + trail + "\"}").statusCode(400);

        JsonNode refused = only(cloudTrailRecords(logs, suffix), "StopLogging", trail);
        assertThat(refused.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(refused.path("userIdentity").path("accessKeyId").asText(), equalTo(intruder.accessKeyId()));
        assertThat(refused.path("requestParameters").isNull(), equalTo(true));
        assertThat(cloudTrail(ACCOUNT, "GetTrailStatus", "{\"Name\":\"" + trail + "\"}").statusCode(200)
                .extract().path("IsLogging"), equalTo(true));
    }

    private void createBucket(String bucket) {
        given().port(baseUri.getPort()).header("Authorization", auth(ACCOUNT, "s3"))
                .when().put("/" + bucket).then().statusCode(200);
        cleanup.register(() -> EnforcementFixtures.removeBucket(baseUri.getPort(), auth(ACCOUNT, "s3"), bucket));
    }

    private void startTrail(String trail, String bucket) {
        createBucket(bucket);
        cloudTrail(ACCOUNT, "CreateTrail", "{\"Name\":\"" + trail + "\",\"S3BucketName\":\"" + bucket + "\"}")
                .statusCode(200);
        cleanup.register(() -> cloudTrail(ACCOUNT, "DeleteTrail", "{\"Name\":\"" + trail + "\"}"));
        cloudTrail(ACCOUNT, "StartLogging", "{\"Name\":\"" + trail + "\"}").statusCode(200);
    }

    private ValidatableResponse cloudTrail(String accessKeyId, String action, String body) {
        return CloudTrailRequests.invokeCloudTrail(auth(accessKeyId, "cloudtrail"), action, body).then();
    }

    /** The CloudTrail records about this test's trails that the writer delivers to {@code bucket}. */
    private List<JsonNode> cloudTrailRecords(String bucket, String suffix) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(ACCOUNT, "s3")).stream()
                .filter(record -> "cloudtrail.amazonaws.com".equals(record.path("eventSource").asText())
                        && record.toString().contains(suffix))
                .toList();
    }

    private static List<JsonNode> byName(List<JsonNode> records, String eventName) {
        return records.stream().filter(record -> eventName.equals(record.path("eventName").asText())).toList();
    }

    private static JsonNode only(List<JsonNode> records, String eventName, String trail) {
        List<JsonNode> found = byName(records, eventName).stream()
                .filter(record -> trail.equals(record.path("requestParameters").path("name").asText())
                        || trail.equals(record.path("requestParameters").path("trailName").asText())
                        || record.path("errorCode").asText().equals("AccessDenied"))
                .toList();
        assertThat(eventName + " about " + trail + " in " + records, found, hasSize(1));
        return found.getFirst();
    }
}
