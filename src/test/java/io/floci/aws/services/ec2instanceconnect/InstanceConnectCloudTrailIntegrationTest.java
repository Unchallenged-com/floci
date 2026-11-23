package io.floci.aws.services.ec2instanceconnect;

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
import java.util.function.Predicate;

import static io.floci.aws.testing.Ec2Requests.ec2;
import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;

/**
 * EC2 Instance Connect's calls reach a trail's log files and event history as CloudTrail management
 * events, with the instance, the OS user and the public key pushed, whether the call succeeded, failed,
 * or was refused by IAM enforcement first.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class InstanceConnectCloudTrailIntegrationTest {

    private static final String ACCOUNT = "661100000775";
    private static final String REGION = "us-east-1";
    private static final String KEY =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@host";

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
    void pushedKeysAreRecordedWithTheInstanceAndTheKey() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-eic-logs-" + suffix;
        startTrail("ct-eic-" + suffix, logs);
        String instanceId = runningInstance();
        String user = "u" + suffix;

        String requestId = send(ACCOUNT, "SendSSHPublicKey", """
                {"InstanceId": "%s", "InstanceOSUser": "%s", "SSHPublicKey": "%s"}""".formatted(instanceId, user, KEY))
                .statusCode(200).extract().path("RequestId");
        send(ACCOUNT, "SendSerialConsoleSSHPublicKey", """
                {"InstanceId": "%s", "SerialPort": 0, "SSHPublicKey": "%s"}""".formatted(instanceId, KEY))
                .statusCode(400);
        send(ACCOUNT, "SendSSHPublicKey", """
                {"InstanceId": "i-0%s0000000f", "InstanceOSUser": "%s", "SSHPublicKey": "%s"}"""
                .formatted(suffix, user, KEY)).statusCode(400);

        List<JsonNode> records = records(logs, instanceId);
        JsonNode pushed = only(records, "SendSSHPublicKey", r -> !r.has("errorCode"));
        assertThat(pushed.path("eventSource").asText(), equalTo("ec2-instance-connect.amazonaws.com"));
        assertThat(pushed.path("eventCategory").asText(), equalTo("Management"));
        assertThat(pushed.path("readOnly").asBoolean(), equalTo(false));
        assertThat(pushed.path("awsRegion").asText(), equalTo(REGION));
        assertThat(pushed.path("sourceIPAddress").asText(), equalTo("127.0.0.1"));
        assertThat(pushed.path("requestParameters").path("instanceId").asText(), equalTo(instanceId));
        assertThat(pushed.path("requestParameters").path("instanceOSUser").asText(), equalTo(user));
        assertThat(pushed.path("requestParameters").path("sSHPublicKey").asText(), equalTo(KEY));
        assertThat(pushed.path("responseElements").path("requestId").asText(), equalTo(requestId));
        assertThat(pushed.path("responseElements").path("success").asBoolean(), equalTo(true));
        assertThat(pushed.path("requestID").asText(), equalTo(requestId));

        JsonNode serial = only(records, "SendSerialConsoleSSHPublicKey", r -> true);
        assertThat(serial.path("readOnly").asBoolean(), equalTo(false));
        assertThat(serial.path("requestParameters").path("serialPort").asInt(-1), equalTo(0));
        assertThat(serial.path("requestParameters").path("sSHPublicKey").asText(), equalTo(KEY));
        assertThat(serial.path("errorCode").asText(), equalTo("SerialConsoleSessionUnsupportedException"));
        assertThat(serial.path("responseElements").isNull(), equalTo(true));

        JsonNode missing = only(records(logs, "i-0" + suffix), "SendSSHPublicKey", r -> true);
        assertThat(missing.path("errorCode").asText(), equalTo("EC2InstanceNotFoundException"));
        assertThat(missing.path("errorMessage").asText(), not(emptyOrNullString()));
        assertThat(missing.path("responseElements").isNull(), equalTo(true));
    }

    @Test
    void aCallIamEnforcementRefusesIsRecordedWithoutItsParameters() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-eic-logs-" + suffix;
        startTrail("ct-eic-" + suffix, logs);
        String user = "ct-user-" + suffix;
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, baseUri.getPort(),
                auth(ACCOUNT, "iam"), user);

        JsonPath answer = send(credentials.accessKeyId(), "SendSSHPublicKey", """
                {"InstanceId": "i-0%s0000000f", "InstanceOSUser": "ec2-user", "SSHPublicKey": "%s"}"""
                .formatted(suffix, KEY)).statusCode(400).extract().jsonPath();

        // AWS records a refusal as AccessDenied, with the message the refusal answered with.
        JsonNode refused = only(records(logs, user), "SendSSHPublicKey", r -> true);
        assertThat(refused.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(refused.path("errorMessage").asText(), equalTo(answer.getString("message")));
        assertThat(refused.path("errorMessage").asText(), containsString("ec2-instance-connect:SendSSHPublicKey"));
        assertThat(refused.path("userIdentity").path("userName").asText(), equalTo(user));
        assertThat(refused.path("requestParameters").isNull(), equalTo(true));
    }

    @Test
    void callsReachEventHistoryWithoutATrail() {
        String instanceId = "i-0" + UUID.randomUUID().toString().substring(0, 8) + "0000000f";
        send(ACCOUNT, "SendSSHPublicKey", """
                {"InstanceId": "%s", "InstanceOSUser": "ec2-user", "SSHPublicKey": "%s"}""".formatted(instanceId, KEY))
                .statusCode(400);

        List<String> events = CloudTrailRequests.invokeCloudTrail(auth(ACCOUNT, "cloudtrail"), "LookupEvents",
                "{\"LookupAttributes\":[{\"AttributeKey\":\"EventName\",\"AttributeValue\":\"SendSSHPublicKey\"}]}")
                .then().statusCode(200).extract().jsonPath().getList("Events.CloudTrailEvent", String.class);
        assertThat(events.stream().filter(event -> event.contains("\"instanceId\":\"" + instanceId + "\"")).count(),
                equalTo(1L));
    }

    /** A running instance in mock mode, terminated after the test. */
    private String runningInstance() {
        String instanceId = ec2("RunInstances", ACCOUNT, REGION)
                .formParam("ImageId", "ami-0abcdef1234567890")
                .formParam("InstanceType", "t3.micro")
                .formParam("MinCount", "1").formParam("MaxCount", "1")
                .post("/").then().statusCode(200)
                .extract().path("RunInstancesResponse.instancesSet.item.instanceId");
        cleanup.register(() -> ec2("TerminateInstances", ACCOUNT, REGION).formParam("InstanceId.1", instanceId)
                .post("/").then().statusCode(200));
        // Mock mode settles a launch on the first DescribeInstances; a key needs a running instance.
        ec2("DescribeInstances", ACCOUNT, REGION).formParam("InstanceId.1", instanceId).post("/").then()
                .statusCode(200);
        return instanceId;
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

    private ValidatableResponse send(String accessKeyId, String action, String body) {
        return given().port(baseUri.getPort())
                .header("Authorization", auth(accessKeyId, REGION, "ec2-instance-connect"))
                .header("X-Amz-Target", "AWSEC2InstanceConnectService." + action)
                .contentType("application/x-amz-json-1.1")
                .body(body)
                .when().post("/")
                .then();
    }

    /** The EC2 Instance Connect records that name {@code marker}, read from the log files delivered to {@code bucket}. */
    private List<JsonNode> records(String bucket, String marker) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(ACCOUNT, "s3")).stream()
                .filter(record -> "ec2-instance-connect.amazonaws.com".equals(record.path("eventSource").asText())
                        && record.toString().contains(marker))
                .toList();
    }

    private static JsonNode only(List<JsonNode> records, String eventName, Predicate<JsonNode> which) {
        List<JsonNode> found = records.stream()
                .filter(record -> eventName.equals(record.path("eventName").asText()))
                .filter(which)
                .toList();
        assertThat(eventName + " in " + records, found, hasSize(1));
        return found.getFirst();
    }
}
