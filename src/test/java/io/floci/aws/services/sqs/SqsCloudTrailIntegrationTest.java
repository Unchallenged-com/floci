package io.floci.aws.services.sqs;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.aws.services.cloudtrail.CloudTrailLogWriter;
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.zip.GZIPInputStream;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;

/**
 * SQS's control plane calls reach a trail's log files as CloudTrail management events, whether SQS
 * ran them, refused them, or IAM enforcement refused them first; its data plane calls do not.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class SqsCloudTrailIntegrationTest {

    private static final String ACCOUNT = "661100000460";
    private static final String REGION = "us-east-1";
    private static final ObjectMapper MAPPER = new ObjectMapper();

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
    void controlPlaneCallsAreRecordedAsManagementEvents() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String name = "ct-queue-" + suffix;
        String logs = "ct-sqs-logs-" + suffix;
        startTrail("ct-sqs-" + suffix, logs);

        String queueUrl = sqs(ACCOUNT, "CreateQueue", """
                {"QueueName": "%s", "Attributes": {"VisibilityTimeout": "45"}, "tags": {"Team": "ops"}}"""
                .formatted(name)).statusCode(200).extract().path("QueueUrl");
        cleanup.register(() -> sqs(ACCOUNT, "DeleteQueue", "{\"QueueUrl\": \"" + queueUrl + "\"}"));
        sqs(ACCOUNT, "SetQueueAttributes", """
                {"QueueUrl": "%s", "Attributes": {"Policy": "{\\"Version\\":\\"2012-10-17\\",\\"Statement\\":[]}"}}"""
                .formatted(queueUrl)).statusCode(200);
        sqs(ACCOUNT, "TagQueue", "{\"QueueUrl\": \"" + queueUrl + "\", \"Tags\": {\"Env\": \"" + suffix + "\"}}")
                .statusCode(200);
        sqs(ACCOUNT, "SendMessage", "{\"QueueUrl\": \"" + queueUrl + "\", \"MessageBody\": \"m-" + suffix + "\"}")
                .statusCode(200);
        sqs(ACCOUNT, "GetQueueAttributes", "{\"QueueUrl\": \"" + queueUrl + "\", \"AttributeNames\": [\"All\"]}")
                .statusCode(200);
        sqs(ACCOUNT, "ListMessageMoveTasks", "{\"SourceArn\": \"arn:aws:sqs:" + REGION + ":" + ACCOUNT + ":"
                + name + "\"}");
        sqs(ACCOUNT, "PurgeQueue", "{\"QueueUrl\": \"" + queueUrl + "\"}").statusCode(200);
        sqs(ACCOUNT, "DeleteQueue", "{\"QueueUrl\": \"" + queueUrl + "-missing\"}").statusCode(400);
        sqs(ACCOUNT, "DeleteQueue", "{\"QueueUrl\": \"" + queueUrl + "\"}").statusCode(200);

        List<JsonNode> records = sqsRecords(logs, suffix);

        JsonNode created = only(records, "CreateQueue", ACCOUNT);
        assertThat(created.path("eventSource").asText(), equalTo("sqs.amazonaws.com"));
        assertThat(created.path("eventCategory").asText(), equalTo("Management"));
        assertThat(created.path("managementEvent").asBoolean(), equalTo(true));
        assertThat(created.path("readOnly").asBoolean(), equalTo(false));
        assertThat(created.path("awsRegion").asText(), equalTo(REGION));
        assertThat(created.path("recipientAccountId").asText(), equalTo(ACCOUNT));
        assertThat(created.path("sourceIPAddress").asText(), equalTo("127.0.0.1"));
        assertThat(created.path("userAgent").asText(), not(emptyOrNullString()));
        assertThat(created.path("requestParameters").path("queueName").asText(), equalTo(name));
        assertThat(created.path("requestParameters").path("attributes").path("VisibilityTimeout").asText(),
                equalTo("45"));
        assertThat(created.path("requestParameters").path("tags").path("Team").asText(), equalTo("ops"));
        assertThat(created.path("responseElements").path("queueUrl").asText(), equalTo(queueUrl));

        JsonNode policy = only(records, "SetQueueAttributes", ACCOUNT);
        assertThat(policy.path("requestParameters").path("queueUrl").asText(), equalTo(queueUrl));
        assertThat(policy.path("requestParameters").path("attributes").path("Policy").asText(),
                matchesPattern("\\{\"Version\":\"2012-10-17\".*"));
        assertThat(policy.path("responseElements").isNull(), equalTo(true));

        assertThat(only(records, "TagQueue", ACCOUNT).path("requestParameters").path("tags").path("Env").asText(),
                equalTo(suffix));
        assertThat(only(records, "PurgeQueue", ACCOUNT).path("readOnly").asBoolean(), equalTo(false));

        JsonNode listed = only(records, "ListMessageMoveTasks", ACCOUNT);
        assertThat(listed.path("readOnly").asBoolean(), equalTo(true));
        assertThat(listed.path("responseElements").isNull(), equalTo(true));

        List<JsonNode> deletes = records.stream().filter(r -> "DeleteQueue".equals(r.path("eventName").asText()))
                .toList();
        assertThat(deletes, hasSize(2));
        JsonNode missing = deletes.stream().filter(r -> r.has("errorCode")).findFirst().orElseThrow();
        assertThat(missing.path("errorCode").asText(), equalTo("QueueDoesNotExist"));
        assertThat(missing.path("errorMessage").asText(), not(emptyOrNullString()));
        assertThat(missing.path("responseElements").isNull(), equalTo(true));

        assertThat(records.stream().filter(r -> "SendMessage".equals(r.path("eventName").asText())
                || "GetQueueAttributes".equals(r.path("eventName").asText())).toList(), hasSize(0));
    }

    @Test
    void aCallIamEnforcementRefusesIsRecordedWithoutItsParameters() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-sqs-logs-" + suffix;
        startTrail("ct-sqs-" + suffix, logs);
        String user = "ct-user-" + suffix;
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, baseUri.getPort(),
                auth(ACCOUNT, "iam"), user);

        sqs(credentials.accessKeyId(), "CreateQueue", "{\"QueueName\": \"ct-refused-" + suffix + "\"}")
                .statusCode(400);

        JsonNode refused = only(sqsRecords(logs, suffix), "CreateQueue", credentials.accessKeyId());
        assertThat(refused.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(refused.path("errorMessage").asText(),
                matchesPattern("User: arn:aws:iam::" + ACCOUNT + ":\\S+ is not authorized to perform: sqs:CreateQueue .*"));
        assertThat(refused.path("userIdentity").path("userName").asText(), equalTo(user));
        assertThat(refused.path("requestParameters").isNull(), equalTo(true));
        assertThat(refused.path("responseElements").isNull(), equalTo(true));
    }

    @Test
    void aQueryProtocolCallIsNotRecorded() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-sqs-logs-" + suffix;
        startTrail("ct-sqs-" + suffix, logs);
        String queueUrl = given().port(baseUri.getPort()).header("Authorization", auth(ACCOUNT, "sqs"))
                .contentType("application/x-www-form-urlencoded")
                .formParam("Action", "CreateQueue").formParam("Version", "2012-11-05")
                .formParam("QueueName", "ct-query-" + suffix)
                .when().post("/").then().statusCode(200)
                .extract().xmlPath().getString("CreateQueueResponse.CreateQueueResult.QueueUrl");
        cleanup.register(() -> sqs(ACCOUNT, "DeleteQueue", "{\"QueueUrl\": \"" + queueUrl + "\"}"));

        assertThat(sqsRecords(logs, suffix), hasSize(0));
    }

    private void startTrail(String trail, String bucket) {
        given().port(baseUri.getPort()).header("Authorization", auth(ACCOUNT, "s3"))
                .when().put("/" + bucket).then().statusCode(200);
        cleanup.register(() -> EnforcementFixtures.removeBucket(baseUri.getPort(), auth(ACCOUNT, "s3"), bucket));
        cloudTrail("CreateTrail", "{\"Name\":\"" + trail + "\",\"S3BucketName\":\"" + bucket + "\"}");
        cleanup.register(() -> cloudTrail("DeleteTrail", "{\"Name\":\"" + trail + "\"}"));
        cloudTrail("StartLogging", "{\"Name\":\"" + trail + "\"}");
    }

    private void cloudTrail(String action, String body) {
        given().port(baseUri.getPort())
                .header("Authorization", auth(ACCOUNT, "cloudtrail"))
                .header("X-Amz-Target", "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101." + action)
                .contentType("application/x-amz-json-1.1")
                .body(body)
                .when().post("/")
                .then().statusCode(200);
    }

    private ValidatableResponse sqs(String accessKeyId, String action, String body) {
        return given().port(baseUri.getPort())
                .header("Authorization", auth(accessKeyId, REGION, "sqs"))
                .header("X-Amz-Target", "AmazonSQS." + action)
                .contentType("application/x-amz-json-1.0")
                .body(body)
                .when().post("/")
                .then();
    }

    /** The SQS records of this test's calls, read from the log files the writer delivers to {@code bucket}. */
    private List<JsonNode> sqsRecords(String bucket, String suffix) throws IOException {
        writer.flushNow();
        List<String> keys = given().port(baseUri.getPort()).header("Authorization", auth(ACCOUNT, "s3"))
                .queryParam("list-type", "2").queryParam("prefix", "AWSLogs/")
                .when().get("/" + bucket)
                .then().statusCode(200).extract().xmlPath().getList("ListBucketResult.Contents.Key");
        List<JsonNode> records = new ArrayList<>();
        for (String key : keys) {
            byte[] gz = given().port(baseUri.getPort()).header("Authorization", auth(ACCOUNT, "s3"))
                    .when().get("/" + bucket + "/" + key)
                    .then().statusCode(200).extract().asByteArray();
            try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(gz))) {
                for (JsonNode record : MAPPER.readTree(in.readAllBytes()).path("Records")) {
                    if ("sqs.amazonaws.com".equals(record.path("eventSource").asText())
                            && (record.path("requestParameters").toString().contains(suffix)
                                || record.path("userIdentity").path("userName").asText().contains(suffix))) {
                        records.add(record);
                    }
                }
            }
        }
        return records;
    }

    private static JsonNode only(List<JsonNode> records, String eventName, String accessKeyId) {
        List<JsonNode> found = records.stream()
                .filter(record -> eventName.equals(record.path("eventName").asText()))
                .filter(record -> accessKeyId.equals(record.path("userIdentity").path("accessKeyId").asText()))
                .toList();
        assertThat(eventName + " by " + accessKeyId + " in " + records, found, hasSize(1));
        return found.getFirst();
    }
}
