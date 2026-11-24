package io.floci.aws.services.ssoadmin;

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
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;

/**
 * IAM Identity Center's public operations reach a trail as management events under {@code sso.amazonaws.com},
 * whether IAM Identity Center ran them, refused them, or IAM enforcement refused them first.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class SsoAdminCloudTrailIntegrationTest {

    private static final String ROOT = "test";
    private static final String REGION = "us-east-1";
    private static final String MEMBER_ACCOUNT = "111111111111";

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
    void permissionSetAndAssignmentCallsAreRecorded() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-sso-admin-logs-" + suffix;
        startTrail("ct-sso-admin-" + suffix, logs);
        String instanceArn = sso(ROOT, "ListInstances", "{}").statusCode(200).extract().path("Instances[0].InstanceArn");
        String name = "CtAdmins" + suffix;

        String permissionSetArn = sso(ROOT, "CreatePermissionSet", """
                {"InstanceArn": "%s", "Name": "%s", "SessionDuration": "PT2H"}""".formatted(instanceArn, name))
                .statusCode(200).extract().path("PermissionSet.PermissionSetArn");
        String permissionSet = "{\"InstanceArn\": \"" + instanceArn + "\", \"PermissionSetArn\": \""
                + permissionSetArn + "\"}";
        cleanup.register(() -> sso(ROOT, "DeletePermissionSet", permissionSet));
        String principalId = UUID.randomUUID().toString();
        String assignment = """
                {"InstanceArn": "%s", "TargetId": "%s", "TargetType": "AWS_ACCOUNT", "PermissionSetArn": "%s",
                 "PrincipalType": "GROUP", "PrincipalId": "%s"}"""
                .formatted(instanceArn, MEMBER_ACCOUNT, permissionSetArn, principalId);
        sso(ROOT, "CreateAccountAssignment", assignment).statusCode(200);
        cleanup.register(() -> sso(ROOT, "DeleteAccountAssignment", assignment));
        sso(ROOT, "DescribePermissionSet", permissionSet).statusCode(200);
        String unknownArn = permissionSetArn.replaceFirst("ps-[0-9a-f]+$", "ps-0000000000000000");
        sso(ROOT, "DescribePermissionSet", permissionSet.replace(permissionSetArn, unknownArn)).statusCode(400);

        List<JsonNode> records = ssoRecords(logs, permissionSetArn, unknownArn);

        JsonNode created = only(records, "CreatePermissionSet");
        assertThat(created.path("eventSource").asText(), equalTo("sso.amazonaws.com"));
        assertThat(created.path("eventCategory").asText(), equalTo("Management"));
        assertThat(created.path("readOnly").asBoolean(), equalTo(false));
        assertThat(created.path("awsRegion").asText(), equalTo(REGION));
        assertThat(created.path("sourceIPAddress").asText(), not(emptyOrNullString()));
        assertThat(created.path("requestParameters").path("instanceArn").asText(), equalTo(instanceArn));
        assertThat(created.path("requestParameters").path("name").asText(), equalTo(name));
        assertThat(created.path("requestParameters").path("sessionDuration").asText(), equalTo("PT2H"));
        JsonNode answered = created.path("responseElements").path("permissionSet");
        assertThat(answered.path("permissionSetArn").asText(), equalTo(permissionSetArn));
        assertThat(answered.path("createdDate").asText(),
                matchesPattern("[A-Z][a-z]{2} \\d{1,2}, \\d{4}, \\d{1,2}:\\d{2}:\\d{2} [AP]M"));

        JsonNode assigned = only(records, "CreateAccountAssignment");
        assertThat(assigned.path("readOnly").asBoolean(), equalTo(false));
        assertThat(assigned.path("requestParameters").path("targetId").asText(), equalTo(MEMBER_ACCOUNT));
        assertThat(assigned.path("requestParameters").path("targetType").asText(), equalTo("AWS_ACCOUNT"));
        assertThat(assigned.path("requestParameters").path("principalType").asText(), equalTo("GROUP"));
        assertThat(assigned.path("requestParameters").path("principalId").asText(), equalTo(principalId));
        JsonNode status = assigned.path("responseElements").path("accountAssignmentCreationStatus");
        assertThat(status.path("permissionSetArn").asText(), equalTo(permissionSetArn));
        assertThat(status.path("requestId").asText(), not(emptyOrNullString()));

        List<JsonNode> described = records.stream()
                .filter(r -> "DescribePermissionSet".equals(r.path("eventName").asText())).toList();
        assertThat(described, hasSize(2));
        JsonNode read = described.stream().filter(r -> !r.has("errorCode")).findFirst().orElseThrow();
        assertThat(read.path("readOnly").asBoolean(), equalTo(true));
        assertThat(read.path("requestParameters").path("permissionSetArn").asText(), equalTo(permissionSetArn));
        assertThat(read.path("responseElements").isNull(), equalTo(true));
        JsonNode missing = described.stream().filter(r -> r.has("errorCode")).findFirst().orElseThrow();
        assertThat(missing.path("errorCode").asText(), equalTo("ResourceNotFoundException"));
        assertThat(missing.path("errorMessage").asText(), not(emptyOrNullString()));
        assertThat(missing.path("requestParameters").path("permissionSetArn").asText(), equalTo(unknownArn));
        assertThat(missing.path("responseElements").isNull(), equalTo(true));
    }

    @Test
    void regionAndSessionConfigurationCallsTheGuideDoesNotListAreRecorded() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-sso-admin-logs-" + suffix;
        startTrail("ct-sso-admin-" + suffix, logs);
        String instanceArn = sso(ROOT, "ListInstances", "{}").statusCode(200).extract().path("Instances[0].InstanceArn");
        String applicationArn = sso(ROOT, "CreateApplication", """
                {"InstanceArn": "%s", "ApplicationProviderArn": "arn:aws:sso::aws:applicationProvider/custom",
                 "Name": "ct-app-%s"}""".formatted(instanceArn, suffix))
                .statusCode(200).extract().path("ApplicationArn");
        String application = "{\"ApplicationArn\": \"" + applicationArn + "\"}";
        cleanup.register(() -> sso(ROOT, "DeleteApplication", application));

        sso(ROOT, "ListRegions", "{\"InstanceArn\": \"" + instanceArn + "\"}").statusCode(200);
        sso(ROOT, "PutApplicationSessionConfiguration", """
                {"ApplicationArn": "%s", "UserBackgroundSessionApplicationStatus": "ENABLED"}"""
                .formatted(applicationArn)).statusCode(200);
        sso(ROOT, "GetApplicationSessionConfiguration", application).statusCode(200);

        List<JsonNode> records = ssoRecords(logs, instanceArn, applicationArn);

        JsonNode regions = only(records, "ListRegions");
        assertThat(regions.path("eventSource").asText(), equalTo("sso.amazonaws.com"));
        assertThat(regions.path("readOnly").asBoolean(), equalTo(true));
        assertThat(regions.path("requestParameters").path("instanceArn").asText(), equalTo(instanceArn));
        assertThat(regions.path("responseElements").isNull(), equalTo(true));

        JsonNode put = only(records, "PutApplicationSessionConfiguration");
        assertThat(put.path("readOnly").asBoolean(), equalTo(false));
        assertThat(put.path("requestParameters").path("applicationArn").asText(), equalTo(applicationArn));
        assertThat(put.path("requestParameters").path("userBackgroundSessionApplicationStatus").asText(),
                equalTo("ENABLED"));
        assertThat(put.path("responseElements").isNull(), equalTo(true));

        JsonNode get = only(records, "GetApplicationSessionConfiguration");
        assertThat(get.path("readOnly").asBoolean(), equalTo(true));
        assertThat(get.path("requestParameters").path("applicationArn").asText(), equalTo(applicationArn));
        assertThat(get.path("responseElements").isNull(), equalTo(true));
    }

    @Test
    void aCallIamEnforcementRefusesIsRecordedWithoutItsParameters() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-sso-admin-logs-" + suffix;
        startTrail("ct-sso-admin-" + suffix, logs);
        String user = "ct-sso-user-" + suffix;
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, baseUri.getPort(), auth(ROOT, "iam"),
                user);
        String instanceArn = sso(ROOT, "ListInstances", "{}").statusCode(200).extract().path("Instances[0].InstanceArn");

        JsonPath answer = sso(credentials.accessKeyId(), "CreatePermissionSet",
                "{\"InstanceArn\": \"" + instanceArn + "\", \"Name\": \"CtRefused" + suffix + "\"}")
                .statusCode(400).extract().jsonPath();

        JsonNode refused = only(ssoRecords(logs, credentials.accessKeyId()), "CreatePermissionSet");
        assertThat(refused.path("eventSource").asText(), equalTo("sso.amazonaws.com"));
        assertThat(refused.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(refused.path("errorMessage").asText(), equalTo(answer.getString("message")));
        assertThat(refused.path("errorMessage").asText(), containsString("sso:CreatePermissionSet"));
        assertThat(refused.path("userIdentity").path("userName").asText(), equalTo(user));
        assertThat(refused.path("requestParameters").isNull(), equalTo(true));
        assertThat(refused.path("responseElements").isNull(), equalTo(true));
    }

    private void startTrail(String trail, String bucket) {
        given().port(baseUri.getPort()).header("Authorization", auth(ROOT, "s3"))
                .when().put("/" + bucket).then().statusCode(200);
        cleanup.register(() -> EnforcementFixtures.removeBucket(baseUri.getPort(), auth(ROOT, "s3"), bucket));
        cloudTrail("CreateTrail", "{\"Name\":\"" + trail + "\",\"S3BucketName\":\"" + bucket + "\"}");
        cleanup.register(() -> cloudTrail("DeleteTrail", "{\"Name\":\"" + trail + "\"}"));
        cloudTrail("StartLogging", "{\"Name\":\"" + trail + "\"}");
    }

    private static void cloudTrail(String action, String body) {
        CloudTrailRequests.invokeCloudTrail(auth(ROOT, "cloudtrail"), action, body).then().statusCode(200);
    }

    private ValidatableResponse sso(String accessKeyId, String action, String body) {
        return given().port(baseUri.getPort())
                .header("Authorization", auth(accessKeyId, REGION, "sso"))
                .header("X-Amz-Target", "SWBExternalService." + action)
                .contentType("application/x-amz-json-1.1")
                .body(body)
                .when().post("/")
                .then();
    }

    /**
     * The sso.amazonaws.com records that name one of {@code markers}, read from the log files delivered to
     * {@code bucket}.
     */
    private List<JsonNode> ssoRecords(String bucket, String... markers) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(ROOT, "s3")).stream()
                .filter(record -> "sso.amazonaws.com".equals(record.path("eventSource").asText())
                        && List.of(markers).stream().anyMatch(marker -> record.toString().contains(marker)))
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
