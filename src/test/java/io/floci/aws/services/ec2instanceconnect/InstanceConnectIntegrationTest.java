package io.floci.aws.services.ec2instanceconnect;

import io.floci.aws.testing.EnforcementFixtures;
import io.floci.aws.testing.EnforcementFixtures.Session;
import io.floci.aws.testing.EnforcementFixtures.UserCredentials;
import io.floci.aws.testing.PartitionCleanup;
import io.floci.aws.testing.RestAssuredJsonUtils;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.net.URI;
import java.util.List;
import java.util.UUID;

import static io.floci.aws.testing.Ec2Requests.ec2;
import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;

@QuarkusTest
class InstanceConnectIntegrationTest {

    private static final String JSON_1_1 = "application/x-amz-json-1.1";
    private static final String ED25519 =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@host";
    private static final String ACCOUNT = "661100000868";
    private static final String REGION = "us-east-1";

    @TestHTTPResource("/")
    static URI baseUri;

    @Inject
    InstanceConnectKeys keys;

    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    private static Response send(String instanceId, String key) {
        return given()
                .header("X-Amz-Target", "AWSEC2InstanceConnectService.SendSSHPublicKey")
                .contentType(JSON_1_1)
                .body("{\"InstanceId\":\"" + instanceId + "\",\"InstanceOSUser\":\"ec2-user\",\"SSHPublicKey\":\""
                        + key + "\"}")
                .post("/");
    }

    @Test
    void sendsAKeyToARunningInstanceAndRejectsWhatAwsRejects() {
        String instanceId = ec2("RunInstances", "000000000000", "us-east-1")
                .formParam("ImageId", "ami-0abcdef1234567890")
                .formParam("InstanceType", "t3.micro")
                .formParam("MinCount", "1").formParam("MaxCount", "1")
                .post("/").then().statusCode(200)
                .extract().path("RunInstancesResponse.instancesSet.item.instanceId");
        try {
            // Mock mode settles a launch on the first DescribeInstances; the key needs a running instance.
            ec2("DescribeInstances", "000000000000", "us-east-1").formParam("InstanceId.1", instanceId)
                    .post("/").then().statusCode(200)
                    .body("DescribeInstancesResponse.reservationSet.item.instancesSet.item.instanceState.name",
                            equalTo("running"));
            send(instanceId, ED25519).then().statusCode(200)
                    .body("Success", equalTo(true))
                    .body("RequestId", not(emptyString()));
            send(instanceId, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 " + "c".repeat(80)).then().statusCode(400)
                    .body("__type", equalTo("InvalidArgsException"));
        } finally {
            ec2("TerminateInstances", "000000000000", "us-east-1").formParam("InstanceId.1", instanceId)
                    .post("/").then().statusCode(200);
        }
    }

    @Test
    void unknownInstanceIsAModeledError() {
        send("i-0000000000000000f", ED25519).then().statusCode(400)
                .body("__type", equalTo("EC2InstanceNotFoundException"));
    }

    @Test
    void aKeyPushedByAnIamUserIsServedAsThatUsers() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String user = "eic-user-" + suffix;
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, baseUri.getPort(),
                auth(ACCOUNT, "iam"), user);
        String instanceId = runningInstance();

        signedBy(credentials.accessKeyId(), null, instanceId).then().statusCode(200);

        assertThat(callers(instanceId), contains("arn:aws:iam::" + ACCOUNT + ":user/" + user));
    }

    @Test
    void aKeyPushedByARoleSessionIsServedAsThatSessions() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String role = "eic-role-" + suffix;
        String roleArn = EnforcementFixtures.createRole(cleanup, baseUri.getPort(), ACCOUNT, "/", role, """
                {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                  "Action":"ec2-instance-connect:SendSSHPublicKey","Resource":"*"}]}""");
        Session session = EnforcementFixtures.assumeRole(baseUri.getPort(), ACCOUNT, roleArn);
        String instanceId = runningInstance();

        signedBy(session.accessKeyId(), session.sessionToken(), instanceId).then().statusCode(200);

        assertThat(callers(instanceId), contains("arn:aws:sts::" + ACCOUNT + ":assumed-role/" + role + "/"
                + EnforcementFixtures.SESSION_NAME));
    }

    private Response signedBy(String accessKeyId, String sessionToken, String instanceId) {
        RequestSpecification request = given().port(baseUri.getPort())
                .header("Authorization", auth(accessKeyId, REGION, "ec2-instance-connect"));
        if (sessionToken != null) {
            request = request.header("X-Amz-Security-Token", sessionToken);
        }
        return request
                .header("X-Amz-Target", "AWSEC2InstanceConnectService.SendSSHPublicKey")
                .contentType(JSON_1_1)
                .body("{\"InstanceId\":\"" + instanceId + "\",\"InstanceOSUser\":\"ec2-user\",\"SSHPublicKey\":\""
                        + ED25519 + "\"}")
                .post("/");
    }

    /** The callers the signed active-keys document names, as the instance's agent reads them from IMDS. */
    private List<String> callers(String instanceId) {
        return keys.activeKeysDocument(REGION, instanceId, "ec2-user").orElseThrow().lines()
                .filter(line -> line.startsWith("#Caller="))
                .map(line -> line.substring("#Caller=".length()))
                .toList();
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
        ec2("DescribeInstances", ACCOUNT, REGION).formParam("InstanceId.1", instanceId).post("/").then()
                .statusCode(200);
        return instanceId;
    }
}
