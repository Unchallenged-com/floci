package io.floci.aws.services.ssm;

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
 * Systems Manager's calls reach a trail's log files and event history as CloudTrail management
 * events, whether Systems Manager ran them, refused them, or IAM enforcement refused them first, and
 * no record carries a parameter's value or the commands a SendCommand runs.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class SsmCloudTrailIntegrationTest {

    private static final String ACCOUNT = "661100000774";
    private static final String REGION = "us-east-1";
    private static final String HIDDEN = "HIDDEN_DUE_TO_SECURITY_REASONS";
    /** The record's timestamp format: "Aug 2, 2024, 11:08:56 AM". */
    private static final String RECORD_TIME = "[A-Z][a-z]{2} \\d{1,2}, \\d{4}, \\d{1,2}:\\d{2}:\\d{2} (AM|PM)";

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
    void parameterCallsAreRecordedWithoutTheirValues() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String name = "/ct/" + suffix + "/db-password";
        String other = "/ct/" + suffix + "/db-user";
        String logs = "ct-ssm-logs-" + suffix;
        startTrail("ct-ssm-" + suffix, logs);

        ssm(ACCOUNT, "PutParameter", """
                {"Name": "%s", "Value": "secret-%s", "Type": "SecureString"}""".formatted(name, suffix))
                .statusCode(200);
        ssm(ACCOUNT, "PutParameter", """
                {"Name": "%s", "Value": "plain-%s", "Type": "String"}""".formatted(other, suffix))
                .statusCode(200);
        ssm(ACCOUNT, "GetParameter", "{\"Name\": \"" + name + "\", \"WithDecryption\": true}").statusCode(200);
        String arn = ssm(ACCOUNT, "GetParameters", """
                {"Names": ["%s", "%s"], "WithDecryption": true}""".formatted(name, other))
                .statusCode(200).extract().path("Parameters.find { it.Name == '" + name + "' }.ARN");
        ssm(ACCOUNT, "GetParameter", "{\"Name\": \"" + name + "-missing\"}").statusCode(400);

        List<JsonNode> records = ssmRecords(logs, suffix);
        assertThat(records.toString(), not(containsString("secret-" + suffix)));
        assertThat(records.toString(), not(containsString("plain-" + suffix)));

        List<JsonNode> puts = named(records, "PutParameter");
        assertThat(puts, hasSize(2));
        JsonNode put = puts.stream().filter(r -> name.equals(r.path("requestParameters").path("name").asText()))
                .findFirst().orElseThrow();
        assertThat(put.path("eventSource").asText(), equalTo("ssm.amazonaws.com"));
        assertThat(put.path("eventCategory").asText(), equalTo("Management"));
        assertThat(put.path("managementEvent").asBoolean(), equalTo(true));
        assertThat(put.path("readOnly").asBoolean(), equalTo(false));
        assertThat(put.path("awsRegion").asText(), equalTo(REGION));
        assertThat(put.path("sourceIPAddress").asText(), equalTo("127.0.0.1"));
        assertThat(put.path("requestParameters").path("type").asText(), equalTo("SecureString"));
        assertThat(put.path("requestParameters").path("value").asText(), equalTo(HIDDEN));
        assertThat(put.path("responseElements").path("version").isIntegralNumber(), equalTo(true));

        JsonNode read = only(records, "GetParameter", r -> !r.has("errorCode"));
        assertThat(read.path("readOnly").asBoolean(), equalTo(true));
        assertThat(read.path("requestParameters").path("name").asText(), equalTo(name));
        assertThat(read.path("requestParameters").path("withDecryption").asBoolean(), equalTo(true));
        assertThat(read.path("responseElements").isNull(), equalTo(true));

        JsonNode batch = only(records, "GetParameters", r -> true);
        assertThat(batch.path("readOnly").asBoolean(), equalTo(true));
        assertThat(batch.path("requestParameters").path("names").size(), equalTo(2));
        assertThat(batch.path("responseElements").isNull(), equalTo(true));
        assertThat(batch.path("resources").size(), equalTo(2));
        assertThat(batch.path("resources").toString(), containsString("\"ARN\":\"" + arn + "\""));
        assertThat(batch.path("resources").get(0).path("accountId").asText(), equalTo(ACCOUNT));

        JsonNode missing = only(records, "GetParameter", r -> r.has("errorCode"));
        assertThat(missing.path("errorCode").asText(), equalTo("ParameterNotFound"));
        assertThat(missing.path("errorMessage").asText(), not(emptyOrNullString()));
        assertThat(missing.path("responseElements").isNull(), equalTo(true));
    }

    @Test
    void sendCommandAndDocumentSharingAreRecordedWithoutTheCommands() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-ssm-logs-" + suffix;
        String instance = "i-0" + suffix + "77400000";
        String document = "ct-doc-" + suffix;
        startTrail("ct-ssm-" + suffix, logs);

        String commandId = ssm(ACCOUNT, "SendCommand", """
                {"InstanceIds": ["%s"], "DocumentName": "AWS-RunShellScript",
                 "Parameters": {"commands": ["echo run-%s"]}}""".formatted(instance, suffix))
                .statusCode(200).extract().path("Command.CommandId");
        ssm(ACCOUNT, "GetCommandInvocation", """
                {"CommandId": "%s", "InstanceId": "%s"}""".formatted(commandId, instance));
        ssm(ACCOUNT, "CreateDocument", """
                {"Name": "%s", "DocumentType": "Command",
                 "Content": "{\\"schemaVersion\\":\\"2.2\\",\\"mainSteps\\":[]}"}""".formatted(document))
                .statusCode(200);
        ssm(ACCOUNT, "ModifyDocumentPermission", """
                {"Name": "%s", "PermissionType": "Share", "AccountIdsToAdd": ["111122223333"]}""".formatted(document))
                .statusCode(200);

        List<JsonNode> records = ssmRecords(logs, suffix);
        assertThat(records.toString(), not(containsString("echo run-" + suffix)));

        JsonNode sent = only(records, "SendCommand", r -> true);
        assertThat(sent.path("readOnly").asBoolean(), equalTo(false));
        assertThat(sent.path("requestParameters").path("documentName").asText(), equalTo("AWS-RunShellScript"));
        assertThat(sent.path("requestParameters").path("instanceIds").get(0).asText(), equalTo(instance));
        assertThat(sent.path("requestParameters").path("parameters").asText(), equalTo(HIDDEN));
        JsonNode command = sent.path("responseElements").path("command");
        assertThat(command.path("commandId").asText(), equalTo(commandId));
        assertThat(command.path("parameters").asText(), equalTo(HIDDEN));
        assertThat(command.path("expiresAfter").asText(), matchesPattern(RECORD_TIME));
        assertThat(command.path("requestedDateTime").asText(), matchesPattern(RECORD_TIME));

        JsonNode invocation = only(records, "GetCommandInvocation", r -> true);
        assertThat(invocation.path("readOnly").asBoolean(), equalTo(true));
        assertThat(invocation.path("requestParameters").path("commandId").asText(), equalTo(commandId));
        assertThat(invocation.path("requestParameters").path("instanceId").asText(), equalTo(instance));
        assertThat(invocation.path("responseElements").isNull(), equalTo(true));

        JsonNode created = only(records, "CreateDocument", r -> true);
        assertThat(created.path("requestParameters").path("name").asText(), equalTo(document));
        assertThat(created.path("responseElements").path("documentDescription").path("name").asText(),
                equalTo(document));

        JsonNode shared = only(records, "ModifyDocumentPermission", r -> true);
        assertThat(shared.path("readOnly").asBoolean(), equalTo(false));
        assertThat(shared.path("requestParameters").path("name").asText(), equalTo(document));
        assertThat(shared.path("requestParameters").path("permissionType").asText(), equalTo("Share"));
        assertThat(shared.path("requestParameters").path("accountIdsToAdd").get(0).asText(), equalTo("111122223333"));
        assertThat(shared.path("responseElements").isNull(), equalTo(true));
    }

    @Test
    void aCallIamEnforcementRefusesIsRecordedWithoutItsParameters() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-ssm-logs-" + suffix;
        startTrail("ct-ssm-" + suffix, logs);
        String user = "ct-user-" + suffix;
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, baseUri.getPort(),
                auth(ACCOUNT, "iam"), user);

        JsonPath answer = ssm(credentials.accessKeyId(), "GetParameter",
                "{\"Name\": \"/ct/" + suffix + "/refused\", \"WithDecryption\": true}")
                .statusCode(400).extract().jsonPath();

        // AWS records a refusal as AccessDenied, with the message the refusal answered with.
        List<JsonNode> records = ssmRecords(logs, user);
        JsonNode refused = only(records, "GetParameter", r -> true);
        assertThat(refused.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(refused.path("errorMessage").asText(), equalTo(answer.getString("message")));
        assertThat(refused.path("errorMessage").asText(), containsString("ssm:GetParameter"));
        assertThat(refused.path("userIdentity").path("userName").asText(), equalTo(user));
        assertThat(refused.path("requestParameters").isNull(), equalTo(true));
        assertThat(refused.path("responseElements").isNull(), equalTo(true));
    }

    @Test
    void callsReachEventHistoryWithoutATrail() {
        String name = "/ct-history/" + UUID.randomUUID().toString().substring(0, 8);
        ssm(ACCOUNT, "PutParameter", "{\"Name\": \"" + name + "\", \"Value\": \"v\", \"Type\": \"String\"}")
                .statusCode(200);
        ssm(ACCOUNT, "DeleteParameter", "{\"Name\": \"" + name + "\"}").statusCode(200);

        List<String> events = CloudTrailRequests.invokeCloudTrail(auth(ACCOUNT, "cloudtrail"), "LookupEvents",
                "{\"LookupAttributes\":[{\"AttributeKey\":\"EventName\",\"AttributeValue\":\"DeleteParameter\"}]}")
                .then().statusCode(200).extract().jsonPath().getList("Events.CloudTrailEvent", String.class);
        assertThat(events.stream().filter(event -> event.contains("\"eventSource\":\"ssm.amazonaws.com\"")
                && event.contains("\"name\":\"" + name + "\"")).count(), equalTo(1L));
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

    private ValidatableResponse ssm(String accessKeyId, String action, String body) {
        return given().port(baseUri.getPort())
                .header("Authorization", auth(accessKeyId, REGION, "ssm"))
                .header("X-Amz-Target", "AmazonSSM." + action)
                .contentType("application/x-amz-json-1.1")
                .body(body)
                .when().post("/")
                .then();
    }

    /** The Systems Manager records that name {@code marker}, read from the log files delivered to {@code bucket}. */
    private List<JsonNode> ssmRecords(String bucket, String marker) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(ACCOUNT, "s3")).stream()
                .filter(record -> "ssm.amazonaws.com".equals(record.path("eventSource").asText())
                        && record.toString().contains(marker))
                .toList();
    }

    private static List<JsonNode> named(List<JsonNode> records, String eventName) {
        return records.stream().filter(record -> eventName.equals(record.path("eventName").asText())).toList();
    }

    private static JsonNode only(List<JsonNode> records, String eventName,
                                 Predicate<JsonNode> which) {
        List<JsonNode> found = named(records, eventName).stream().filter(which).toList();
        assertThat(eventName + " in " + records, found, hasSize(1));
        return found.getFirst();
    }
}
