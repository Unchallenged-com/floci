package io.floci.aws.services.guardduty;

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
import io.restassured.specification.RequestSpecification;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;

/**
 * The GuardDuty calls Floci serves reach a trail's log files under their own names, with their path, query and
 * body members as GuardDuty's JSON names them, and a refused call with its members and the refusal's message.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class GuardDutyCloudTrailIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String AGENT = "guardduty-cloudtrail-test/1.0";

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
    void managementCallsAreRecordedWithTheirMembers() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-guardduty-logs-" + suffix;
        startTrail(account, "ct-guardduty-" + suffix, logs);
        String key = auth(account, REGION, "guardduty");
        String email = "member-" + suffix + "@example.com";

        String detectorId = call(key).body("{\"enable\":true,\"clientToken\":\"token-" + suffix + "\"}")
                .post("/detector").then().statusCode(200).extract().path("detectorId");
        cleanup.register(() -> call(key).delete("/detector/" + detectorId));
        call(key).get("/detector/" + detectorId).then().statusCode(200);
        call(key).queryParam("maxResults", 5).get("/detector").then().statusCode(200);
        call(key).body("{\"enable\":false,\"findingPublishingFrequency\":\"ONE_HOUR\"}")
                .post("/detector/" + detectorId).then().statusCode(200);

        String destinationId = call(key).body("{\"destinationType\":\"S3\",\"destinationProperties\":{"
                        + "\"destinationArn\":\"arn:aws:s3:::findings-" + suffix + "\","
                        + "\"kmsKeyArn\":\"arn:aws:kms:us-east-1:" + account + ":key/k\"}}")
                .post("/detector/" + detectorId + "/publishingDestination").then().statusCode(200)
                .extract().path("destinationId");
        call(key).body("{\"destinationProperties\":{\"destinationArn\":\"arn:aws:s3:::elsewhere-" + suffix + "\"}}")
                .post("/detector/" + detectorId + "/publishingDestination/" + destinationId).then().statusCode(200);
        call(key).delete("/detector/" + detectorId + "/publishingDestination/" + destinationId)
                .then().statusCode(200);

        call(key).body("{\"accountDetails\":[{\"accountId\":\"222222222222\",\"email\":\"" + email + "\"}]}")
                .post("/detector/" + detectorId + "/member").then().statusCode(200);

        String detectorArn = "arn:aws:guardduty:" + REGION + ":" + account + ":detector/" + detectorId;
        String tags = "/tags/" + URLEncoder.encode(detectorArn, StandardCharsets.UTF_8);
        call(key).urlEncodingEnabled(false).body("{\"tags\":{\"team\":\"security\"}}").post(tags)
                .then().statusCode(204);
        call(key).urlEncodingEnabled(false).queryParam("tagKeys", "team").delete(tags).then().statusCode(204);

        String bucket = "gd-ct-" + suffix;
        String planId = call(key).body("{\"role\":\"arn:aws:iam::" + account + ":role/scan\","
                        + "\"protectedResource\":{\"s3Bucket\":{\"bucketName\":\"" + bucket + "\"}}}")
                .post("/malware-protection-plan").then().statusCode(200).extract().path("malwareProtectionPlanId");
        cleanup.register(() -> call(key).delete("/malware-protection-plan/" + planId));
        call(key).delete("/malware-protection-plan/" + planId).then().statusCode(200);

        call(key).body("{\"adminAccountId\":\"" + account + "\"}").post("/admin/enable").then().statusCode(200);
        cleanup.register(() -> call(key).body("{\"adminAccountId\":\"" + account + "\"}").post("/admin/disable"));
        call(key).body("{\"adminAccountId\":\"" + account + "\"}").post("/admin/disable").then().statusCode(200);

        call(key).delete("/detector/" + detectorId).then().statusCode(200);

        List<JsonNode> records = guardDutyRecords(account, logs);
        assertThat(records.toString(), not(containsString(email)));

        JsonNode create = only(records, "CreateDetector");
        assertThat(create.path("eventSource").asText(), equalTo("guardduty.amazonaws.com"));
        assertThat(create.path("readOnly").asBoolean(true), equalTo(false));
        assertThat(create.path("userAgent").asText(), equalTo(AGENT));
        assertThat(create.path("requestParameters").path("enable").asBoolean(), equalTo(true));
        assertThat(create.path("requestParameters").path("clientToken").asText(), equalTo("token-" + suffix));
        assertThat(create.path("responseElements").path("detectorId").asText(), equalTo(detectorId));

        JsonNode get = only(records, "GetDetector");
        assertThat(get.path("readOnly").asBoolean(), equalTo(true));
        assertThat(get.path("requestParameters").path("detectorId").asText(), equalTo(detectorId));
        assertThat(get.path("responseElements").isNull(), equalTo(true));

        JsonNode list = only(records, "ListDetectors");
        assertThat(list.path("readOnly").asBoolean(), equalTo(true));
        assertThat(list.path("requestParameters").path("maxResults").isInt(), equalTo(true));
        assertThat(list.path("requestParameters").path("maxResults").asInt(), equalTo(5));

        JsonNode update = only(records, "UpdateDetector");
        assertThat(update.path("requestParameters").path("detectorId").asText(), equalTo(detectorId));
        assertThat(update.path("requestParameters").path("enable").isBoolean(), equalTo(true));
        assertThat(update.path("requestParameters").path("enable").asBoolean(true), equalTo(false));
        assertThat(update.path("requestParameters").path("findingPublishingFrequency").asText(),
                equalTo("ONE_HOUR"));
        assertThat(update.path("responseElements").isNull(), equalTo(true));

        JsonNode destination = only(records, "CreatePublishingDestination");
        assertThat(destination.path("requestParameters").path("destinationType").asText(), equalTo("S3"));
        assertThat(destination.path("requestParameters").path("destinationProperties").path("destinationArn")
                .asText(), equalTo("arn:aws:s3:::findings-" + suffix));
        assertThat(destination.path("responseElements").path("destinationId").asText(), equalTo(destinationId));
        assertThat(only(records, "UpdatePublishingDestination").path("requestParameters")
                .path("destinationProperties").path("destinationArn").asText(),
                equalTo("arn:aws:s3:::elsewhere-" + suffix));
        JsonNode removed = only(records, "DeletePublishingDestination").path("requestParameters");
        assertThat(removed.path("detectorId").asText(), equalTo(detectorId));
        assertThat(removed.path("destinationId").asText(), equalTo(destinationId));

        JsonNode members = only(records, "CreateMembers").path("requestParameters");
        assertThat(members.path("detectorId").asText(), equalTo(detectorId));
        assertThat(members.path("accountDetails").path(0).path("accountId").asText(), equalTo("222222222222"));
        assertThat(members.path("accountDetails").path(0).has("email"), equalTo(false));

        JsonNode tagged = only(records, "TagResource").path("requestParameters");
        assertThat(tagged.path("resourceArn").asText(), equalTo(detectorArn));
        assertThat(tagged.path("tags").path("team").asText(), equalTo("security"));
        JsonNode untagged = only(records, "UntagResource").path("requestParameters");
        assertThat(untagged.path("tagKeys").path(0).asText(), equalTo("team"));

        JsonNode plan = only(records, "CreateMalwareProtectionPlan");
        assertThat(plan.path("requestParameters").path("protectedResource").path("s3Bucket").path("bucketName")
                .asText(), equalTo(bucket));
        assertThat(plan.path("responseElements").path("malwareProtectionPlanId").asText(), equalTo(planId));
        assertThat(only(records, "DeleteMalwareProtectionPlan").path("requestParameters")
                .path("malwareProtectionPlanId").asText(), equalTo(planId));

        assertThat(only(records, "EnableOrganizationAdminAccount").path("requestParameters")
                .path("adminAccountId").asText(), equalTo(account));
        assertThat(only(records, "DisableOrganizationAdminAccount").path("requestParameters")
                .path("adminAccountId").asText(), equalTo(account));

        JsonNode delete = only(records, "DeleteDetector");
        assertThat(delete.path("requestParameters").path("detectorId").asText(), equalTo(detectorId));
        assertThat(delete.path("responseElements").isNull(), equalTo(true));
    }

    @Test
    void aRefusedCallKeepsItsMembersAndAWriteItsMessage() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-guardduty-logs-" + suffix;
        startTrail(account, "ct-guardduty-" + suffix, logs);
        String user = "ct-user-" + suffix;
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, baseUri.getPort(),
                auth(account, "iam"), user);
        String key = auth(credentials.accessKeyId(), REGION, "guardduty");
        String detectorId = "d" + suffix;

        call(key).body("{\"enable\":false}").post("/detector/" + detectorId).then().statusCode(403);
        call(key).get("/detector/" + detectorId).then().statusCode(403);

        List<JsonNode> records = guardDutyRecords(account, logs);
        JsonNode update = only(records, "UpdateDetector");
        assertThat(update.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(update.has("errorMessage"), equalTo(false));
        assertThat(update.path("userIdentity").path("userName").asText(), equalTo(user));
        assertThat(update.path("requestParameters").path("detectorId").asText(), equalTo(detectorId));
        assertThat(update.path("requestParameters").path("enable").isBoolean(), equalTo(true));
        assertThat(update.path("responseElements").path("message").asText(),
                containsString("guardduty:UpdateDetector"));

        JsonNode get = only(records, "GetDetector");
        assertThat(get.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(get.has("errorMessage"), equalTo(false));
        assertThat(get.path("requestParameters").path("detectorId").asText(), equalTo(detectorId));
        assertThat(get.path("responseElements").isNull(), equalTo(true));
    }

    private RequestSpecification call(String authorization) {
        return given().port(baseUri.getPort()).contentType("application/json").header("Authorization", authorization)
                .header("User-Agent", AGENT);
    }

    private static String account() {
        return "6615" + String.format("%08d", (int) (Math.random() * 100_000_000));
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

    /** The GuardDuty records of {@code account}, read from the log files delivered to {@code bucket}. */
    private List<JsonNode> guardDutyRecords(String account, String bucket) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(account, "s3")).stream()
                .filter(record -> "guardduty.amazonaws.com".equals(record.path("eventSource").asText()))
                .toList();
    }

    private static JsonNode only(List<JsonNode> records, String eventName) {
        List<JsonNode> found = records.stream().filter(record -> eventName.equals(record.path("eventName").asText()))
                .toList();
        assertThat(eventName + " in " + records, found, hasSize(1));
        return found.getFirst();
    }
}
