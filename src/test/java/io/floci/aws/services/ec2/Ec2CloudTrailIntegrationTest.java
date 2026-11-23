package io.floci.aws.services.ec2;

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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.startsWith;

/**
 * The EC2 calls Floci records reach a trail's log files written as EC2 records write them: lists
 * as {@code {"items": [...]}}, {@code requestId} and {@code _return} in the answer, user data hidden.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class Ec2CloudTrailIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String IMAGE = "ami-0abcdef1234567890";

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
    void callsAreRecordedInEc2sOwnSchema() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-ec2-logs-" + suffix;
        startTrail(account, "ct-ec2-" + suffix, logs);

        String instanceId = ec2(account, Map.of("Action", "RunInstances", "ImageId", IMAGE, "InstanceType", "t3.micro",
                "MinCount", "1", "MaxCount", "1", "TagSpecification.1.ResourceType", "instance",
                "TagSpecification.1.Tag.1.Key", "team", "TagSpecification.1.Tag.1.Value", suffix))
                .statusCode(200).extract().xmlPath().getString("RunInstancesResponse.instancesSet.item[0].instanceId");
        ec2(account, Map.of("Action", "StopInstances", "InstanceId.1", instanceId, "Force", "true")).statusCode(200);
        ec2(account, Map.of("Action", "ModifyInstanceAttribute", "InstanceId", instanceId,
                "UserData.Value", "c2VjcmV0")).statusCode(200);
        ec2(account, Map.of("Action", "StartInstances", "InstanceId.1", instanceId)).statusCode(200);
        String groupId = ec2(account, Map.of("Action", "CreateSecurityGroup", "GroupName", "ct-" + suffix,
                "GroupDescription", "ct")).statusCode(200).extract().xmlPath().getString("CreateSecurityGroupResponse.groupId");
        ec2(account, Map.of("Action", "AuthorizeSecurityGroupIngress", "GroupId", groupId,
                "IpPermissions.1.IpProtocol", "tcp", "IpPermissions.1.FromPort", "22", "IpPermissions.1.ToPort", "22",
                "IpPermissions.1.IpRanges.1.CidrIp", "203.0.113.0/24")).statusCode(200);
        ec2(account, Map.of("Action", "DeleteNetworkAcl", "NetworkAclId", "acl-0000000000000000" + suffix.charAt(0)))
                .statusCode(400);
        ec2(account, Map.of("Action", "TerminateInstances", "InstanceId.1", instanceId)).statusCode(200);

        List<JsonNode> records = ec2Records(account, logs);

        JsonNode run = only(records, "RunInstances");
        assertThat(run.path("eventSource").asText(), equalTo("ec2.amazonaws.com"));
        assertThat(run.path("readOnly").asBoolean(), equalTo(false));
        JsonNode launch = run.path("requestParameters").path("instancesSet").path("items").get(0);
        assertThat(launch.path("imageId").asText(), equalTo(IMAGE));
        assertThat(launch.path("minCount").isNumber(), equalTo(true));
        assertThat(run.path("requestParameters").path("disableApiTermination").asBoolean(true), equalTo(false));
        assertThat(run.path("requestParameters").path("monitoring").path("enabled").asBoolean(true), equalTo(false));
        assertThat(run.path("requestParameters").path("tagSpecificationSet").path("items").get(0).path("tags").get(0)
                .path("value").asText(), equalTo(suffix));
        assertThat(run.path("responseElements").path("requestId").asText(null), notNullValue());
        assertThat(run.path("responseElements").path("instancesSet").path("items").get(0).path("instanceId").asText(),
                equalTo(instanceId));

        JsonNode stop = only(records, "StopInstances");
        assertThat(stop.path("requestParameters").path("force").asBoolean(), equalTo(true));
        assertThat(stop.path("requestParameters").path("instancesSet").path("items").get(0).path("instanceId").asText(),
                equalTo(instanceId));
        assertThat(stop.path("responseElements").path("instancesSet").path("items").get(0).path("currentState")
                .path("code").isNumber(), equalTo(true));

        JsonNode modify = only(records, "ModifyInstanceAttribute");
        assertThat(modify.path("requestParameters").path("userData").asText(), equalTo("<sensitiveDataRemoved>"));
        assertThat(modify.path("responseElements").path("_return").asBoolean(), equalTo(true));

        JsonNode ingress = only(records, "AuthorizeSecurityGroupIngress");
        JsonNode rule = ingress.path("requestParameters").path("ipPermissions").path("items").get(0);
        assertThat(rule.path("fromPort").asInt(), equalTo(22));
        assertThat(rule.path("ipRanges").path("items").get(0).path("cidrIp").asText(), equalTo("203.0.113.0/24"));
        assertThat(rule.path("groups").isObject() && rule.path("groups").isEmpty(), equalTo(true));
        assertThat(ingress.path("responseElements").path("_return").asBoolean(), equalTo(true));

        JsonNode missing = only(records, "DeleteNetworkAcl");
        assertThat(missing.path("errorCode").asText(), startsWith("Client."));
        assertThat(missing.path("requestParameters").path("networkAclId").asText(), startsWith("acl-"));

        JsonNode terminate = only(records, "TerminateInstances");
        assertThat(terminate.path("requestParameters").path("skipOsShutdown").asBoolean(true), equalTo(false));

        assertThat(records.stream().filter(r -> "CreateSecurityGroup".equals(r.path("eventName").asText())).toList(),
                hasSize(0));
    }

    @Test
    void aRefusedCallKeepsItsMembers() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-ec2-logs-" + suffix;
        startTrail(account, "ct-ec2-" + suffix, logs);
        String user = "ct-user-" + suffix;
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, baseUri.getPort(),
                auth(account, "iam"), user);

        ec2(credentials.accessKeyId(), Map.of("Action", "RunInstances", "ImageId", IMAGE, "MinCount", "1",
                "MaxCount", "10", "InstanceType", "p2.xlarge")).statusCode(403);

        JsonNode refused = only(ec2Records(account, logs), "RunInstances");
        assertThat(refused.path("errorCode").asText(), equalTo("Client.UnauthorizedOperation"));
        assertThat(refused.path("errorMessage").asText(), startsWith("You are not authorized to perform this operation."));
        assertThat(refused.path("userIdentity").path("userName").asText(), equalTo(user));
        assertThat(refused.path("requestParameters").path("instancesSet").path("items").get(0).path("maxCount").asInt(),
                equalTo(10));
        assertThat(refused.path("responseElements").isNull(), equalTo(true));
    }

    private static String account() {
        return "6613" + String.format("%08d", (int) (Math.random() * 100_000_000));
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

    private ValidatableResponse ec2(String accessKeyId, Map<String, String> form) {
        Map<String, String> params = new LinkedHashMap<>(form);
        params.put("Version", "2016-11-15");
        return given().port(baseUri.getPort())
                .header("Authorization", auth(accessKeyId, REGION, "ec2"))
                .contentType("application/x-www-form-urlencoded")
                .formParams(params)
                .when().post("/")
                .then();
    }

    /** The EC2 records of {@code account}, read from the log files delivered to {@code bucket}. */
    private List<JsonNode> ec2Records(String account, String bucket) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(account, "s3")).stream()
                .filter(record -> "ec2.amazonaws.com".equals(record.path("eventSource").asText()))
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
