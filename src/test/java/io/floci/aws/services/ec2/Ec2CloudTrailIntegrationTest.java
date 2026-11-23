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
import io.restassured.path.xml.XmlPath;
import io.restassured.response.ValidatableResponse;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.startsWith;

/**
 * The EC2 calls Floci records reach a trail's log files written as EC2 records write them: lists
 * as {@code {"items": [...]}}, {@code requestId} and {@code _return} in the answer, user data and key
 * material hidden, members named and typed as the records show them, and the newer calls as their
 * own XML.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class Ec2CloudTrailIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String IMAGE = "ami-0abcdef1234567890";
    private static final String PUBLIC_KEY = Base64.getEncoder().encodeToString(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHEZlat4A5ba//e+02PXRcmk6I3v8/Bn3ZPjEtK3XEwC ct-test"
                    .getBytes(StandardCharsets.UTF_8));

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

        JsonNode group = only(records, "CreateSecurityGroup");
        assertThat(group.path("requestParameters").path("groupDescription").asText(), equalTo("ct"));
        assertThat(group.path("responseElements").path("groupId").asText(), equalTo(groupId));
        assertThat(group.path("responseElements").path("_return").asBoolean(), equalTo(true));
    }

    @Test
    void securityGroupAndNetworkCallsAreRecorded() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-ec2-logs-" + suffix;
        startTrail(account, "ct-ec2-" + suffix, logs);

        String vpcId = ec2(account, form("Action", "CreateVpc", "CidrBlock", "10.40.0.0/16"))
                .statusCode(200).extract().xmlPath().getString("CreateVpcResponse.vpc.vpcId");
        String groupId = ec2(account, form("Action", "CreateSecurityGroup", "GroupName", "ct-" + suffix,
                "GroupDescription", "ct", "VpcId", vpcId))
                .statusCode(200).extract().xmlPath().getString("CreateSecurityGroupResponse.groupId");
        String ruleId = ec2(account, form("Action", "AuthorizeSecurityGroupIngress", "GroupId", groupId,
                "IpPermissions.1.IpProtocol", "tcp", "IpPermissions.1.FromPort", "443", "IpPermissions.1.ToPort", "443",
                "IpPermissions.1.IpRanges.1.CidrIp", "198.51.100.0/24")).statusCode(200).extract().xmlPath()
                .getString("AuthorizeSecurityGroupIngressResponse.securityGroupRuleSet.item[0].securityGroupRuleId");
        ec2(account, form("Action", "ModifySecurityGroupRules", "GroupId", groupId,
                "SecurityGroupRule.1.SecurityGroupRuleId", ruleId,
                "SecurityGroupRule.1.SecurityGroupRule.IpProtocol", "-1",
                "SecurityGroupRule.1.SecurityGroupRule.CidrIpv4", "198.51.100.0/24")).statusCode(200);
        ec2(account, form("Action", "AuthorizeSecurityGroupIngress", "GroupId", groupId, "IpProtocol", "tcp",
                "FromPort", "22", "ToPort", "22", "CidrIp", "203.0.113.0/24")).statusCode(200);
        ec2(account, form("Action", "RevokeSecurityGroupIngress", "GroupId", groupId, "IpProtocol", "tcp",
                "FromPort", "22", "ToPort", "22", "CidrIp", "203.0.113.0/24")).statusCode(200);
        ec2(account, form("Action", "RevokeSecurityGroupEgress", "GroupId", groupId,
                "IpPermissions.1.IpProtocol", "-1", "IpPermissions.1.IpRanges.1.CidrIp", "0.0.0.0/0")).statusCode(200);
        ec2(account, form("Action", "DeleteSecurityGroup", "GroupId", groupId)).statusCode(200);

        String aclId = ec2(account, form("Action", "CreateNetworkAcl", "VpcId", vpcId,
                "TagSpecification.1.ResourceType", "network-acl", "TagSpecification.1.Tag.1.Key", "Name",
                "TagSpecification.1.Tag.1.Value", suffix))
                .statusCode(200).extract().xmlPath().getString("CreateNetworkAclResponse.networkAcl.networkAclId");
        ec2(account, form("Action", "CreateNetworkAclEntry", "NetworkAclId", aclId, "RuleNumber", "20",
                "Protocol", "6", "RuleAction", "allow", "Egress", "false", "CidrBlock", "0.0.0.0/0",
                "PortRange.From", "22", "PortRange.To", "22")).statusCode(200);
        ec2(account, form("Action", "ReplaceNetworkAclEntry", "NetworkAclId", aclId, "RuleNumber", "20",
                "Protocol", "-1", "RuleAction", "allow", "Egress", "false", "CidrBlock", "0.0.0.0/0")).statusCode(200);
        ec2(account, form("Action", "CreateFlowLogs", "ResourceId.1", vpcId, "ResourceType", "VPC",
                "TrafficType", "REJECT", "LogDestinationType", "cloud-watch-logs", "LogGroupName", "ct-" + suffix,
                "DeliverLogsPermissionArn", "arn:aws:iam::" + account + ":role/ct-flow-logs",
                "MaxAggregationInterval", "600")).statusCode(200);

        List<JsonNode> records = ec2Records(account, logs);

        JsonNode group = only(records, "CreateSecurityGroup").path("requestParameters");
        assertThat(group.path("groupName").asText(), equalTo("ct-" + suffix));
        assertThat(group.path("groupDescription").asText(), equalTo("ct"));
        assertThat(group.path("vpcId").asText(), equalTo(vpcId));

        JsonNode modify = only(records, "ModifySecurityGroupRules");
        JsonNode rule = modify.path("requestParameters").path("ModifySecurityGroupRulesRequest");
        assertThat(rule.path("GroupId").asText(), equalTo(groupId));
        assertThat(rule.path("SecurityGroupRule").path("tag").asInt(), equalTo(1));
        assertThat(rule.path("SecurityGroupRule").path("SecurityGroupRuleId").asText(), equalTo(ruleId));
        assertThat(rule.path("SecurityGroupRule").path("SecurityGroupRule").path("IpProtocol").isNumber(),
                equalTo(true));
        JsonNode modified = modify.path("responseElements").path("ModifySecurityGroupRulesResponse");
        assertThat(modified.path("return").asBoolean(), equalTo(true));
        assertThat(modified.path("xmlns").asText(), equalTo("http://ec2.amazonaws.com/doc/2016-11-15/"));
        assertThat(modified.path("requestId").asText(null), notNullValue());

        JsonNode revoke = only(records, "RevokeSecurityGroupIngress");
        assertThat(revoke.path("requestParameters").path("cidrIp").asText(), equalTo("203.0.113.0/24"));
        assertThat(revoke.path("requestParameters").path("fromPort").isNumber(), equalTo(true));
        assertThat(revoke.path("requestParameters").path("ipPermissions").isEmpty(), equalTo(true));
        assertThat(revoke.path("responseElements").path("_return").asBoolean(), equalTo(true));
        JsonNode egress = only(records, "RevokeSecurityGroupEgress").path("requestParameters").path("ipPermissions")
                .path("items").get(0);
        assertThat(egress.path("ipProtocol").asText(), equalTo("-1"));
        assertThat(egress.path("ipRanges").path("items").get(0).path("cidrIp").asText(), equalTo("0.0.0.0/0"));
        assertThat(only(records, "DeleteSecurityGroup").path("requestParameters").path("groupId").asText(),
                equalTo(groupId));

        JsonNode acl = only(records, "CreateNetworkAcl");
        assertThat(acl.path("requestParameters").path("tagSpecificationSet").path("items").get(0).path("resourceType")
                .asText(), equalTo("network-acl"));
        JsonNode created = acl.path("responseElements").path("networkAcl");
        assertThat(created.path("networkAclId").asText(), equalTo(aclId));
        assertThat(created.path("isDefault").isBoolean(), equalTo(true));
        JsonNode defaultEntry = created.path("entrySet").path("items").get(0);
        assertThat(defaultEntry.path("aclProtocol").asText(), equalTo("-1"));
        assertThat(defaultEntry.path("ruleNumber").isNumber(), equalTo(true));
        assertThat(defaultEntry.path("icmpTypeCode").isObject(), equalTo(true));
        assertThat(defaultEntry.path("portRange").isObject(), equalTo(true));

        JsonNode entry = only(records, "CreateNetworkAclEntry");
        assertThat(entry.path("requestParameters").path("aclProtocol").asText(), equalTo("6"));
        assertThat(entry.path("requestParameters").path("ruleNumber").asInt(), equalTo(20));
        assertThat(entry.path("requestParameters").path("egress").isBoolean(), equalTo(true));
        assertThat(entry.path("requestParameters").path("portRange").path("from").asInt(), equalTo(22));
        assertThat(entry.path("requestParameters").path("icmpTypeCode").isEmpty(), equalTo(true));
        assertThat(entry.path("responseElements").path("_return").asBoolean(), equalTo(true));
        JsonNode replace = only(records, "ReplaceNetworkAclEntry").path("requestParameters");
        assertThat(replace.path("aclProtocol").asText(), equalTo("-1"));
        assertThat(replace.path("portRange").isObject() && replace.path("portRange").isEmpty(), equalTo(true));

        JsonNode flowLogs = only(records, "CreateFlowLogs");
        JsonNode request = flowLogs.path("requestParameters").path("CreateFlowLogsRequest");
        assertThat(request.path("ResourceId").path("tag").asInt(), equalTo(1));
        assertThat(request.path("ResourceId").path("content").asText(), equalTo(vpcId));
        assertThat(request.path("TrafficType").asText(), equalTo("REJECT"));
        assertThat(request.path("MaxAggregationInterval").asInt(), equalTo(600));
        JsonNode answer = flowLogs.path("responseElements").path("CreateFlowLogsResponse");
        assertThat(answer.path("flowLogIdSet").path("item").asText(), startsWith("fl-"));
        assertThat(answer.path("unsuccessful").asText(null), equalTo(""));
        assertThat(answer.path("xmlns").asText(), equalTo("http://ec2.amazonaws.com/doc/2016-11-15/"));
    }

    @Test
    void volumeSnapshotImageAndKeyPairCallsAreRecorded() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-ec2-logs-" + suffix;
        startTrail(account, "ct-ec2-" + suffix, logs);

        XmlPath launched = ec2(account, form("Action", "RunInstances", "ImageId", IMAGE, "InstanceType", "t3.micro",
                "MinCount", "1", "MaxCount", "1")).statusCode(200).extract().xmlPath();
        String instanceId = launched.getString("RunInstancesResponse.instancesSet.item[0].instanceId");
        String zone = launched.getString("RunInstancesResponse.instancesSet.item[0].placement.availabilityZone");
        cleanup.register(() -> ec2(account, form("Action", "TerminateInstances", "InstanceId.1", instanceId)));
        await().atMost(Duration.ofSeconds(10)).pollInterval(Duration.ofMillis(100)).untilAsserted(() ->
                assertThat(ec2(account, form("Action", "DescribeInstances", "InstanceId.1", instanceId))
                        .statusCode(200).extract().xmlPath()
                        .getString("DescribeInstancesResponse.reservationSet.item.instancesSet.item.instanceState.name"),
                        equalTo("running")));
        String volumeId = ec2(account, form("Action", "CreateVolume", "AvailabilityZone", zone, "Size", "1",
                "VolumeType", "gp2", "TagSpecification.1.ResourceType", "volume",
                "TagSpecification.1.Tag.1.Key", "team", "TagSpecification.1.Tag.1.Value", suffix))
                .statusCode(200).extract().xmlPath().getString("CreateVolumeResponse.volumeId");
        ec2(account, form("Action", "AttachVolume", "VolumeId", volumeId, "InstanceId", instanceId,
                "Device", "/dev/sdf")).statusCode(200);
        ec2(account, form("Action", "DetachVolume", "VolumeId", volumeId)).statusCode(200);
        String snapshotId = ec2(account, form("Action", "CreateSnapshot", "VolumeId", volumeId))
                .statusCode(200).extract().xmlPath().getString("CreateSnapshotResponse.snapshotId");
        String copyId = ec2(account, form("Action", "CopySnapshot", "SourceRegion", REGION,
                "SourceSnapshotId", snapshotId))
                .statusCode(200).extract().xmlPath().getString("CopySnapshotResponse.snapshotId");
        ec2(account, form("Action", "DeleteSnapshot", "SnapshotId", copyId)).statusCode(200);

        String imageId = ec2(account, form("Action", "CreateImage", "InstanceId", instanceId, "Name", "ct-" + suffix,
                "Description", "ct image"))
                .statusCode(200).extract().xmlPath().getString("CreateImageResponse.imageId");
        String copiedImage = ec2(account, form("Action", "CopyImage", "SourceRegion", REGION, "SourceImageId", imageId,
                "Name", "ct-copy-" + suffix))
                .statusCode(200).extract().xmlPath().getString("CopyImageResponse.imageId");
        ec2(account, form("Action", "DeregisterImage", "ImageId", copiedImage)).statusCode(200);

        ec2(account, form("Action", "CreateKeyPair", "KeyName", "ct-" + suffix)).statusCode(200);
        ec2(account, form("Action", "ImportKeyPair", "KeyName", "ct-imported-" + suffix,
                "PublicKeyMaterial", PUBLIC_KEY)).statusCode(200);
        ec2(account, form("Action", "DeleteKeyPair", "KeyName", "ct-" + suffix)).statusCode(200);

        List<JsonNode> records = ec2Records(account, logs);

        JsonNode volume = only(records, "CreateVolume");
        assertThat(volume.path("requestParameters").path("size").asText(), equalTo("1"));
        assertThat(volume.path("requestParameters").path("size").isTextual(), equalTo(true));
        assertThat(volume.path("requestParameters").path("zone").asText(), equalTo(zone));
        assertThat(volume.path("requestParameters").path("tagSpecificationSet").path("items").get(0).path("tags").get(0)
                .path("value").asText(), equalTo(suffix));
        JsonNode createdVolume = volume.path("responseElements");
        assertThat(createdVolume.path("volumeId").asText(), equalTo(volumeId));
        assertThat(createdVolume.path("size").isTextual(), equalTo(true));
        assertThat(createdVolume.path("zone").asText(), equalTo(zone));
        assertThat(createdVolume.path("createTime").isNumber(), equalTo(true));
        assertThat(createdVolume.has("availabilityZone") || createdVolume.has("attachmentSet"), equalTo(false));

        JsonNode attach = only(records, "AttachVolume");
        assertThat(attach.path("requestParameters").path("device").asText(), equalTo("/dev/sdf"));
        assertThat(attach.path("requestParameters").path("deleteOnTermination").isBoolean(), equalTo(true));
        assertThat(attach.path("responseElements").path("instanceId").asText(), equalTo(instanceId));
        assertThat(attach.path("responseElements").has("deleteOnTermination"), equalTo(false));
        JsonNode detach = only(records, "DetachVolume");
        assertThat(detach.path("requestParameters").path("force").asBoolean(true), equalTo(false));
        assertThat(detach.path("responseElements").path("status").asText(), equalTo("detaching"));

        JsonNode snapshot = only(records, "CreateSnapshot").path("responseElements");
        assertThat(snapshot.path("snapshotId").asText(), equalTo(snapshotId));
        assertThat(snapshot.path("volumeSize").isTextual(), equalTo(true));
        assertThat(snapshot.path("startTime").isNumber(), equalTo(true));
        assertThat(snapshot.has("progress"), equalTo(false));
        JsonNode copy = only(records, "CopySnapshot");
        assertThat(copy.path("requestParameters").path("sourceSnapshotId").asText(), equalTo(snapshotId));
        assertThat(copy.path("responseElements").path("snapshotId").asText(), equalTo(copyId));
        assertThat(only(records, "DeleteSnapshot").path("requestParameters").path("force").asBoolean(true),
                equalTo(false));

        JsonNode image = only(records, "CreateImage");
        assertThat(image.path("requestParameters").path("description").asText(), equalTo("ct image"));
        assertThat(image.path("responseElements").path("imageId").asText(), equalTo(imageId));
        assertThat(only(records, "CopyImage").path("requestParameters").path("sourceImageId").asText(),
                equalTo(imageId));
        assertThat(only(records, "DeregisterImage").path("responseElements").path("_return").asBoolean(),
                equalTo(true));

        JsonNode keyPair = only(records, "CreateKeyPair");
        assertThat(keyPair.path("requestParameters").path("keyType").asText(), equalTo("rsa"));
        assertThat(keyPair.path("requestParameters").path("keyFormat").asText(), equalTo("pem"));
        assertThat(keyPair.path("responseElements").path("keyMaterial").asText(), equalTo("<sensitiveDataRemoved>"));
        assertThat(keyPair.path("responseElements").path("keyPairId").asText(), startsWith("key-"));
        JsonNode imported = only(records, "ImportKeyPair");
        assertThat(imported.path("requestParameters").path("publicKeyMaterial").asText(), equalTo(PUBLIC_KEY));
        assertThat(imported.path("responseElements").path("keyFingerprint").asText(null), notNullValue());

        assertThat(records.stream().filter(r -> "DeleteKeyPair".equals(r.path("eventName").asText())).toList(),
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

    private static Map<String, String> form(String... namesAndValues) {
        Map<String, String> form = new LinkedHashMap<>();
        for (int i = 0; i < namesAndValues.length; i += 2) {
            form.put(namesAndValues[i], namesAndValues[i + 1]);
        }
        return form;
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
