package io.floci.aws.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.aws.testing.AwsTestClients;
import io.floci.aws.testing.CloudTrailRequests;
import io.floci.aws.testing.EnforcementFixtures;
import io.floci.aws.testing.IamEnforcementProfile;
import io.floci.aws.testing.PartitionCleanup;
import io.floci.aws.testing.RestAssuredJsonUtils;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.path.json.JsonPath;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsClient;
import software.amazon.awssdk.services.cloudwatchlogs.model.OutputLogEvent;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.Message;
import software.amazon.awssdk.services.sqs.model.QueueAttributeName;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;

/**
 * A trail with a log group writes each record it delivers as one event of its account's {@code _CloudTrail_} stream,
 * through its role, and a trail with a topic notifies it of each log file, each one only when the role or the topic's
 * policy lets CloudTrail, as {@code GetTrailStatus} reports.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class CloudTrailLogDestinationsIntegrationTest {

    private static final Region REGION = Region.US_EAST_1;
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String TRUST = """
            {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
              "Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"sts:AssumeRole"}]}""";

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
    void recordsReachTheLogGroupAndEachLogFileTheTopic() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        try (CloudWatchLogsClient logs = AwsTestClients.create(CloudWatchLogsClient.builder(), account, REGION, baseUri);
             SnsClient sns = AwsTestClients.create(SnsClient.builder(), account, REGION, baseUri);
             SqsClient sqs = AwsTestClients.create(SqsClient.builder(), account, REGION, baseUri);
             IamClient iam = AwsTestClients.create(IamClient.builder(), account, REGION, baseUri)) {
            String group = "CloudTrail/logs-" + suffix;
            logs.createLogGroup(request -> request.logGroupName(group));
            String groupArn = "arn:aws:logs:us-east-1:" + account + ":log-group:" + group + ":*";
            String roleArn = EnforcementFixtures.createRole(cleanup, baseUri.getPort(), account, "/", "ct-cwl-" + suffix,
                    TRUST, """
                    {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                      "Action":["logs:CreateLogStream","logs:PutLogEvents"],
                      "Resource":"arn:aws:logs:us-east-1:%s:log-group:%s:log-stream:%s_CloudTrail_us-east-1*"}]}"""
                            .formatted(account, group, account));
            String topicName = "ct-topic-" + suffix;
            String topicArn = sns.createTopic(request -> request.name(topicName)).topicArn();
            sns.setTopicAttributes(request -> request.topicArn(topicArn).attributeName("Policy").attributeValue("""
                    {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                      "Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"SNS:Publish","Resource":"%s"}]}"""
                    .formatted(topicArn)));
            String queueUrl = subscribedQueue(sqs, sns, topicArn, "ct-notify-" + suffix);
            String bucket = "ct-dest-" + suffix;
            String trail = "ct-dest-" + suffix;
            startTrail(account, trail, bucket, "\"CloudWatchLogsLogGroupArn\":\"" + groupArn
                    + "\",\"CloudWatchLogsRoleArn\":\"" + roleArn + "\",\"SnsTopicName\":\"" + topicName + "\"");

            String user = "ct-dest-user-" + suffix;
            iam.createUser(request -> request.userName(user));
            writer.flushNow();

            String stream = account + "_CloudTrail_us-east-1";
            List<OutputLogEvent> events = logs.getLogEvents(request -> request.logGroupName(group)
                    .logStreamName(stream).startFromHead(true)).events();
            List<JsonNode> created = new ArrayList<>();
            for (OutputLogEvent event : events) {
                JsonNode record = MAPPER.readTree(event.message());
                if ("CreateUser".equals(record.path("eventName").asText())
                        && user.equals(record.path("requestParameters").path("userName").asText())) {
                    created.add(record);
                    assertThat(event.timestamp(), notNullValue());
                }
            }
            assertThat(created, hasSize(1));
            assertThat(created.getFirst().path("eventSource").asText(), equalTo("iam.amazonaws.com"));

            List<Message> notifications = sqs.receiveMessage(request -> request.queueUrl(queueUrl)
                    .maxNumberOfMessages(10).waitTimeSeconds(2)).messages();
            assertThat(notifications.isEmpty(), equalTo(false));
            JsonNode message = MAPPER.readTree(MAPPER.readTree(notifications.getFirst().body()).path("Message").asText());
            assertThat(message.path("s3Bucket").asText(), equalTo(bucket));
            assertThat(message.path("s3ObjectKey").get(0).asText(), startsWith("AWSLogs/" + account + "/CloudTrail/"));

            JsonPath status = trailStatus(account, trail);
            assertThat(status.get("LatestCloudWatchLogsDeliveryTime"), notNullValue());
            assertThat(status.get("LatestCloudWatchLogsDeliveryError"), nullValue());
            assertThat(status.get("LatestNotificationTime"), notNullValue());
            assertThat(status.get("LatestNotificationError"), nullValue());
        }
    }

    @Test
    void aRoleOrATopicThatDoesNotLetCloudTrailIsReported() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        try (CloudWatchLogsClient logs = AwsTestClients.create(CloudWatchLogsClient.builder(), account, REGION, baseUri);
             SnsClient sns = AwsTestClients.create(SnsClient.builder(), account, REGION, baseUri);
             IamClient iam = AwsTestClients.create(IamClient.builder(), account, REGION, baseUri)) {
            String group = "CloudTrail/denied-" + suffix;
            logs.createLogGroup(request -> request.logGroupName(group));
            String groupArn = "arn:aws:logs:us-east-1:" + account + ":log-group:" + group + ":*";
            String roleArn = EnforcementFixtures.createRole(cleanup, baseUri.getPort(), account, "/",
                    "ct-cwl-denied-" + suffix, TRUST, """
                    {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"logs:CreateLogStream",
                      "Resource":"*"}]}""");
            String topicArn = sns.createTopic(request -> request.name("ct-denied-" + suffix)).topicArn();
            String trail = "ct-denied-" + suffix;
            startTrail(account, trail, "ct-denied-" + suffix, "\"CloudWatchLogsLogGroupArn\":\"" + groupArn
                    + "\",\"CloudWatchLogsRoleArn\":\"" + roleArn + "\",\"SnsTopicName\":\"" + topicArn + "\"");

            iam.createUser(request -> request.userName("ct-denied-user-" + suffix));
            writer.flushNow();

            assertThat(logs.describeLogStreams(request -> request.logGroupName(group)).logStreams(), hasSize(0));
            JsonPath status = trailStatus(account, trail);
            assertThat(status.getString("LatestCloudWatchLogsDeliveryError"), startsWith("AccessDeniedException"));
            assertThat(status.get("LatestCloudWatchLogsDeliveryTime"), nullValue());
            assertThat(status.getString("LatestNotificationError"), startsWith("AuthorizationError"));
            assertThat(status.get("LatestNotificationTime"), nullValue());
        }
    }

    private static String account() {
        return "6616" + String.format("%08d", (int) (Math.random() * 100_000_000));
    }

    private String subscribedQueue(SqsClient sqs, SnsClient sns, String topicArn, String name) {
        String queueUrl = sqs.createQueue(request -> request.queueName(name)).queueUrl();
        String queueArn = sqs.getQueueAttributes(request -> request.queueUrl(queueUrl)
                .attributeNames(QueueAttributeName.QUEUE_ARN)).attributes().get(QueueAttributeName.QUEUE_ARN);
        sqs.setQueueAttributes(request -> request.queueUrl(queueUrl).attributes(Map.of(
                QueueAttributeName.POLICY, """
                {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},
                  "Action":"sqs:SendMessage","Resource":"%s"}]}""".formatted(queueArn))));
        sns.subscribe(request -> request.topicArn(topicArn).protocol("sqs").endpoint(queueArn));
        return queueUrl;
    }

    private void startTrail(String account, String trail, String bucket, String destinations) {
        given().port(baseUri.getPort()).header("Authorization", auth(account, "s3"))
                .when().put("/" + bucket).then().statusCode(200);
        cleanup.register(() -> EnforcementFixtures.removeBucket(baseUri.getPort(), auth(account, "s3"), bucket));
        cloudTrail(account, "CreateTrail", "{\"Name\":\"" + trail + "\",\"S3BucketName\":\"" + bucket + "\","
                + destinations + "}");
        cleanup.register(() -> cloudTrail(account, "DeleteTrail", "{\"Name\":\"" + trail + "\"}"));
        cloudTrail(account, "StartLogging", "{\"Name\":\"" + trail + "\"}");
    }

    private JsonPath trailStatus(String account, String trail) {
        return cloudTrail(account, "GetTrailStatus", "{\"Name\":\"" + trail + "\"}");
    }

    private static JsonPath cloudTrail(String account, String action, String body) {
        return CloudTrailRequests.invokeCloudTrail(auth(account, "cloudtrail"), action, body)
                .then().statusCode(200).extract().jsonPath();
    }
}
