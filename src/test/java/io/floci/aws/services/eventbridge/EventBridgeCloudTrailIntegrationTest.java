package io.floci.aws.services.eventbridge;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.aws.services.cloudtrail.CloudTrailLogWriter;
import io.floci.aws.testing.AwsTestClients;
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
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.Message;
import software.amazon.awssdk.services.sqs.model.QueueAttributeName;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;

/**
 * EventBridge's control plane calls reach a trail's log files as management events, and its data
 * events, {@code PutEvents}, do not; delivering a recorded EventBridge call to the default bus records
 * nothing more.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class EventBridgeCloudTrailIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    /** A timestamp as an EventBridge record writes one ({@code "Mar 7, 2026, 12:51:07 AM"}). */
    private static final String RECORD_TIME = "[A-Z][a-z]{2} \\d{1,2}, \\d{4}, \\d{1,2}:\\d{2}:\\d{2} [AP]M";

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
    void controlPlaneCallsAreRecordedAndPutEventsIsNot() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-events-logs-" + suffix;
        String rule = "ct-rule-" + suffix;
        String connection = "ct-conn-" + suffix;
        startTrail(account, "ct-events-" + suffix, logs);

        String pattern = "{\"source\":[\"aws.ec2\"]}";
        events(account, "PutRule", "{\"Name\": \"" + rule + "\", \"EventPattern\": " + MAPPER.writeValueAsString(pattern)
                + ", \"State\": \"ENABLED\", \"Tags\": [{\"Key\": \"Team\", \"Value\": \"ops\"}]}").statusCode(200);
        events(account, "PutTargets", "{\"Rule\": \"" + rule + "\", \"Targets\": [{\"Id\": \"t1\", \"Arn\": "
                + "\"arn:aws:sqs:us-east-1:" + account + ":ct-target-" + suffix + "\"}]}").statusCode(200);
        events(account, "DescribeRule", "{\"Name\": \"" + rule + "\"}").statusCode(200);
        events(account, "DisableRule", "{\"Name\": \"" + rule + "\"}").statusCode(200);
        events(account, "PutEvents", "{\"Entries\": [{\"Source\": \"ct.test\", \"DetailType\": \"t\", "
                + "\"Detail\": \"{}\"}]}").statusCode(200);
        events(account, "CreateConnection", "{\"Name\": \"" + connection + "\", \"AuthorizationType\": \"API_KEY\", "
                + "\"AuthParameters\": {\"ApiKeyAuthParameters\": {\"ApiKeyName\": \"x-api-key\", "
                + "\"ApiKeyValue\": \"s3cr3t\"}}}").statusCode(200);
        cleanup.register(() -> events(account, "DeleteConnection", "{\"Name\": \"" + connection + "\"}"));
        events(account, "DisableRule", "{\"Name\": \"" + rule + "-missing\"}").statusCode(400);
        events(account, "RemoveTargets", "{\"Rule\": \"" + rule + "\", \"Ids\": [\"t1\"]}").statusCode(200);
        events(account, "DeleteRule", "{\"Name\": \"" + rule + "\"}").statusCode(200);

        List<JsonNode> records = eventsRecords(account, logs);

        JsonNode put = only(records, "PutRule", false);
        assertThat(put.path("eventSource").asText(), equalTo("events.amazonaws.com"));
        assertThat(put.path("apiVersion").asText(), equalTo("2015-10-07"));
        assertThat(put.path("readOnly").asBoolean(), equalTo(false));
        assertThat(put.path("managementEvent").asBoolean(), equalTo(true));
        assertThat(put.path("requestParameters").path("name").asText(), equalTo(rule));
        assertThat(put.path("requestParameters").path("eventPattern").asText(), equalTo(pattern));
        assertThat(put.path("requestParameters").path("state").asText(), equalTo("ENABLED"));
        assertThat(put.path("requestParameters").path("tags").path(0).path("key").asText(), equalTo("Team"));
        assertThat(put.path("responseElements").path("ruleArn").asText(),
                equalTo("arn:aws:events:us-east-1:" + account + ":rule/" + rule));

        JsonNode targets = only(records, "PutTargets", false);
        assertThat(targets.path("requestParameters").path("targets").path(0).path("id").asText(), equalTo("t1"));
        assertThat(targets.path("responseElements").path("failedEntryCount").asInt(), equalTo(0));

        JsonNode described = only(records, "DescribeRule", false);
        assertThat(described.path("readOnly").asBoolean(), equalTo(true));
        assertThat(described.path("responseElements").isNull(), equalTo(true));

        JsonNode disabled = only(records, "DisableRule", false);
        assertThat(disabled.path("readOnly").asBoolean(), equalTo(false));
        assertThat(disabled.path("requestParameters").path("name").asText(), equalTo(rule));
        assertThat(disabled.path("responseElements").isNull(), equalTo(true));

        // The model marks the API key's value sensitive: the record keeps its name and leaves the value out.
        JsonNode created = only(records, "CreateConnection", false);
        JsonNode apiKey = created.path("requestParameters").path("authParameters").path("apiKeyAuthParameters");
        assertThat(apiKey.path("apiKeyName").asText(), equalTo("x-api-key"));
        assertThat(apiKey.has("apiKeyValue"), equalTo(false));
        assertThat(created.toString().contains("s3cr3t"), equalTo(false));
        assertThat(created.path("responseElements").path("connectionArn").asText(), not(emptyOrNullString()));
        assertThat(created.path("responseElements").path("creationTime").asText(), matchesPattern(RECORD_TIME));

        JsonNode missing = only(records, "DisableRule", true);
        assertThat(missing.path("errorCode").asText(), equalTo("ResourceNotFoundException"));
        assertThat(missing.path("errorMessage").asText(), not(emptyOrNullString()));
        assertThat(missing.path("requestParameters").path("name").asText(), equalTo(rule + "-missing"));
        assertThat(missing.path("responseElements").isNull(), equalTo(true));
        JsonNode deleted = only(records, "DeleteRule", false);
        assertThat(deleted.path("requestParameters").path("name").asText(), equalTo(rule));
        assertThat(deleted.path("responseElements").isNull(), equalTo(true));
        only(records, "RemoveTargets", false);

        assertThat(records.stream().filter(r -> "PutEvents".equals(r.path("eventName").asText())).toList(),
                hasSize(0));
    }

    @Test
    void aCallIamEnforcementRefusesIsRecordedWithoutItsParametersOrApiVersion() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-events-logs-" + suffix;
        startTrail(account, "ct-events-" + suffix, logs);
        String user = "ct-user-" + suffix;
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, baseUri.getPort(),
                auth(account, "iam"), user);

        JsonPath answer = events(credentials.accessKeyId(), "DisableRule", "{\"Name\": \"ct-rule-" + suffix + "\"}")
                .statusCode(400).extract().jsonPath();
        events(credentials.accessKeyId(), "ListRules", "{}").statusCode(400);

        // AWS records a refusal as AccessDenied, with the message the refusal answered with.
        List<JsonNode> records = eventsRecords(account, logs);
        JsonNode refused = only(records, "DisableRule", true);
        assertThat(refused.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(refused.path("errorMessage").asText(), equalTo(answer.getString("message")));
        assertThat(refused.path("userIdentity").path("userName").asText(), equalTo(user));
        assertThat(refused.path("requestParameters").isNull(), equalTo(true));
        assertThat(refused.path("responseElements").isNull(), equalTo(true));
        assertThat(refused.has("apiVersion"), equalTo(false));
        assertThat(refused.path("readOnly").asBoolean(), equalTo(false));
        assertThat(only(records, "ListRules", true).path("readOnly").asBoolean(), equalTo(true));
    }

    @Test
    void aRecordedCallDeliveredToTheDefaultBusRecordsNothingMore() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-events-logs-" + suffix;
        String watcher = "ct-watch-" + suffix;
        String watched = "ct-watched-" + suffix;
        try (SqsClient sqs = AwsTestClients.create(SqsClient.builder(), account, Region.US_EAST_1)) {
            String queueUrl = sqs.createQueue(request -> request.queueName(watcher)).queueUrl();
            cleanup.register(() -> sqs.deleteQueue(request -> request.queueUrl(queueUrl)));
            String queueArn = sqs.getQueueAttributes(request -> request.queueUrl(queueUrl)
                    .attributeNames(QueueAttributeName.QUEUE_ARN)).attributes().get(QueueAttributeName.QUEUE_ARN);
            String pattern = "{\"source\":[\"aws.events\"],\"detail-type\":[\"AWS API Call via CloudTrail\"]}";
            events(account, "PutRule", "{\"Name\": \"" + watcher + "\", \"EventPattern\": "
                    + MAPPER.writeValueAsString(pattern) + "}").statusCode(200);
            cleanup.register(() -> events(account, "DeleteRule", "{\"Name\": \"" + watcher + "\", \"Force\": true}"));
            events(account, "PutTargets", "{\"Rule\": \"" + watcher + "\", \"Targets\": [{\"Id\": \"q\", \"Arn\": \""
                    + queueArn + "\"}]}").statusCode(200);
            cleanup.register(() -> events(account, "RemoveTargets", "{\"Rule\": \"" + watcher + "\", \"Ids\": [\"q\"]}"));
            startTrail(account, "ct-events-" + suffix, logs);

            events(account, "PutRule", "{\"Name\": \"" + watched + "\", \"ScheduleExpression\": \"rate(1 day)\"}")
                    .statusCode(200);
            cleanup.register(() -> events(account, "DeleteRule", "{\"Name\": \"" + watched + "\"}"));

            List<JsonNode> delivered = receive(sqs, queueUrl, 1, 5);
            // Wait on for anything a delivery would have recorded and delivered in turn.
            delivered.addAll(receive(sqs, queueUrl, 0, 3));
            assertThat(delivered, hasSize(1));
            assertThat(delivered.getFirst().path("source").asText(), equalTo("aws.events"));
            assertThat(delivered.getFirst().path("detail").path("eventName").asText(), equalTo("PutRule"));
            assertThat(delivered.getFirst().path("detail").path("requestParameters").path("name").asText(),
                    equalTo(watched));

            List<String> recorded = eventsRecords(account, logs).stream()
                    .map(record -> record.path("eventName").asText()).toList();
            assertThat(recorded, contains("PutRule"));
        }
    }

    /** An account of its own, so that this test reads only its own records. */
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

    private ValidatableResponse events(String accessKeyId, String action, String body) {
        return given().port(baseUri.getPort())
                .header("Authorization", auth(accessKeyId, REGION, "events"))
                .header("X-Amz-Target", "AWSEvents." + action)
                .contentType("application/x-amz-json-1.1")
                .body(body)
                .when().post("/")
                .then();
    }

    /** The EventBridge records of {@code account}, read from the log files delivered to {@code bucket}. */
    private List<JsonNode> eventsRecords(String account, String bucket) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(account, "s3")).stream()
                .filter(record -> "events.amazonaws.com".equals(record.path("eventSource").asText()))
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

    /** The events on {@code queueUrl}, waiting up to {@code seconds} for {@code expected} of them. */
    private static List<JsonNode> receive(SqsClient sqs, String queueUrl, int expected, int seconds)
            throws IOException {
        List<JsonNode> received = new ArrayList<>();
        for (int attempt = 0; attempt < seconds && (expected == 0 || received.size() < expected); attempt++) {
            for (Message message : sqs.receiveMessage(request -> request.queueUrl(queueUrl).maxNumberOfMessages(10)
                    .waitTimeSeconds(1)).messages()) {
                received.add(MAPPER.readTree(message.body()));
            }
        }
        return received;
    }
}
