package io.floci.aws.services.sns;

import com.fasterxml.jackson.databind.JsonNode;
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
import io.restassured.specification.RequestSpecification;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.SnsException;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The SNS management calls Floci records reach a trail's log files and the account's event history under their own
 * names, with their members as the model names and types them, whether they are made over the Query protocol or
 * JSON; the data events and the confirmations and unsubscriptions made without credentials do not.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class SnsCloudTrailIntegrationTest {

    private static final Region REGION = Region.US_EAST_1;
    /** The account an unsigned request is served in. */
    private static final String DEFAULT_ACCOUNT = "000000000000";

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
    void topicAndSubscriptionCallsAreRecordedOverBothProtocols() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-sns-logs-" + suffix;
        startTrail(account, "ct-sns-" + suffix, logs);
        String topic = "ct-topic-" + suffix;
        String queueArn = "arn:aws:sqs:us-east-1:" + account + ":ct-queue-" + suffix;
        String policy = "{\"Version\":\"2012-10-17\",\"Statement\":[]}";

        String topicArn;
        String subscriptionArn;
        try (SnsClient sns = AwsTestClients.create(SnsClient.builder(), account, REGION, baseUri)) {
            topicArn = sns.createTopic(request -> request.name(topic)).topicArn();
            subscriptionArn = sns.subscribe(request -> request.topicArn(topicArn).protocol("sqs")
                    .endpoint(queueArn).returnSubscriptionArn(true)).subscriptionArn();
            sns.subscribe(request -> request.topicArn(topicArn).protocol("email").endpoint("soc@example.com"));
            sns.setTopicAttributes(request -> request.topicArn(topicArn).attributeName("Policy")
                    .attributeValue(policy));
            sns.getTopicAttributes(request -> request.topicArn(topicArn));
            sns.listTopics();
            assertThrows(SnsException.class, () -> sns.getTopicAttributes(request -> request
                    .topicArn(topicArn + "-missing")));
            assertThrows(SnsException.class, () -> sns.subscribe(request -> request
                    .topicArn(topicArn + "-missing").protocol("sqs").endpoint(queueArn)));
            sns.publish(request -> request.topicArn(topicArn).message("not a management event"));
        }
        json(account, "Unsubscribe", "{\"SubscriptionArn\":\"" + subscriptionArn + "\"}");
        json(account, "DeleteTopic", "{\"TopicArn\":\"" + topicArn + "\"}");

        List<JsonNode> records = snsRecords(account, logs);

        JsonNode create = only(records, "CreateTopic");
        assertThat(create.path("eventSource").asText(), equalTo("sns.amazonaws.com"));
        assertThat(create.path("readOnly").asBoolean(true), equalTo(false));
        assertThat(create.path("requestParameters").path("name").asText(), equalTo(topic));
        assertThat(create.path("responseElements").path("topicArn").asText(), equalTo(topicArn));

        List<JsonNode> subscriptions = records.stream()
                .filter(r -> "Subscribe".equals(r.path("eventName").asText())).toList();
        assertThat(subscriptions, hasSize(3));
        JsonNode sqs = subscriptions.stream().filter(r -> !r.has("errorCode")
                && "sqs".equals(r.path("requestParameters").path("protocol").asText())).findFirst().orElseThrow();
        assertThat(sqs.path("requestParameters").path("topicArn").asText(), equalTo(topicArn));
        assertThat(sqs.path("requestParameters").path("endpoint").asText(), equalTo(queueArn));
        assertThat(sqs.path("requestParameters").path("returnSubscriptionArn").isBoolean(), equalTo(true));
        assertThat(sqs.path("responseElements").path("subscriptionArn").asText(), equalTo(subscriptionArn));
        JsonNode email = subscriptions.stream()
                .filter(r -> "email".equals(r.path("requestParameters").path("protocol").asText()))
                .findFirst().orElseThrow();
        assertThat(email.path("requestParameters").path("endpoint").asText(), equalTo("REDACTED"));
        JsonNode failed = subscriptions.stream().filter(r -> r.has("errorCode")).findFirst().orElseThrow();
        assertThat(failed.path("errorCode").asText(), equalTo("NotFoundException"));
        assertThat(failed.path("requestParameters").path("topicArn").asText(), equalTo(topicArn + "-missing"));
        assertThat(failed.path("responseElements").isNull(), equalTo(true));

        JsonNode attributes = only(records, "SetTopicAttributes");
        assertThat(attributes.path("requestParameters").path("attributeName").asText(), equalTo("Policy"));
        assertThat(attributes.path("requestParameters").path("attributeValue").asText(), equalTo(policy));
        assertThat(attributes.path("responseElements").isNull(), equalTo(true));

        List<JsonNode> reads = records.stream()
                .filter(r -> "GetTopicAttributes".equals(r.path("eventName").asText())).toList();
        assertThat(reads, hasSize(2));
        JsonNode read = reads.stream().filter(r -> !r.has("errorCode")).findFirst().orElseThrow();
        assertThat(read.path("readOnly").asBoolean(), equalTo(true));
        assertThat(read.path("responseElements").isNull(), equalTo(true));
        JsonNode missing = reads.stream().filter(r -> r.has("errorCode")).findFirst().orElseThrow();
        assertThat(missing.path("errorCode").asText(), equalTo("NotFoundException"));
        assertThat(missing.path("requestParameters").path("topicArn").asText(), equalTo(topicArn + "-missing"));
        assertThat(missing.path("responseElements").isNull(), equalTo(true));
        assertThat(records.stream().anyMatch(r -> "ListTopics".equals(r.path("eventName").asText())),
                equalTo(true));

        assertThat(only(records, "Unsubscribe").path("requestParameters").path("subscriptionArn").asText(),
                equalTo(subscriptionArn));
        JsonNode delete = only(records, "DeleteTopic");
        assertThat(delete.path("requestParameters").path("topicArn").asText(), equalTo(topicArn));
        assertThat(delete.path("responseElements").isNull(), equalTo(true));

        assertThat(records.stream().filter(r -> "Publish".equals(r.path("eventName").asText())).toList(),
                hasSize(0));
    }

    @Test
    void aRefusedCallIsRecordedWithoutItsMembers() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-sns-logs-" + suffix;
        startTrail(account, "ct-sns-" + suffix, logs);
        String user = "ct-sns-user-" + suffix;
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, baseUri.getPort(),
                auth(account, "iam"), user);

        String message;
        try (SnsClient sns = AwsTestClients.create(SnsClient.builder(), credentials.accessKeyId(),
                credentials.secretAccessKey(), REGION, baseUri)) {
            SnsException error = assertThrows(SnsException.class, () -> sns.deleteTopic(request -> request
                    .topicArn("arn:aws:sns:us-east-1:" + account + ":ct-alerts-" + suffix)));
            message = error.awsErrorDetails().errorMessage();
        }

        JsonNode refused = only(snsRecords(account, logs), "DeleteTopic");
        assertThat(refused.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(refused.path("errorMessage").asText(), equalTo(message));
        assertThat(refused.path("userIdentity").path("userName").asText(), equalTo(user));
        assertThat(refused.path("requestParameters").isNull(), equalTo(true));
    }

    @Test
    void confirmationsAndUnsubscriptionsWithoutCredentialsAreNotRecorded() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-sns-anon-logs-" + suffix;
        startTrail(DEFAULT_ACCOUNT, "ct-sns-anon-" + suffix, logs);
        String topicArn;
        String unsigned;
        String signed;
        try (SnsClient sns = AwsTestClients.create(SnsClient.builder(), DEFAULT_ACCOUNT, REGION, baseUri)) {
            topicArn = sns.createTopic(request -> request.name("ct-anon-" + suffix)).topicArn();
            unsigned = sns.subscribe(request -> request.topicArn(topicArn).protocol("sqs")
                    .endpoint("arn:aws:sqs:us-east-1:" + DEFAULT_ACCOUNT + ":ct-anon-a-" + suffix)
                    .returnSubscriptionArn(true)).subscriptionArn();
            signed = sns.subscribe(request -> request.topicArn(topicArn).protocol("sqs")
                    .endpoint("arn:aws:sqs:us-east-1:" + DEFAULT_ACCOUNT + ":ct-anon-b-" + suffix)
                    .returnSubscriptionArn(true)).subscriptionArn();
        }

        // The links a confirmation request and a notification carry are followed without credentials.
        given().port(baseUri.getPort()).queryParam("Action", "Unsubscribe").queryParam("SubscriptionArn", unsigned)
                .when().get("/").then().statusCode(200);
        given().port(baseUri.getPort()).queryParam("Action", "ConfirmSubscription").queryParam("TopicArn", topicArn)
                .queryParam("Token", "unsigned-" + suffix).when().get("/");
        query(DEFAULT_ACCOUNT, "Unsubscribe", "SubscriptionArn", signed);
        given().port(baseUri.getPort()).header("Authorization", auth(DEFAULT_ACCOUNT, REGION.id(), "sns"))
                .contentType("application/x-www-form-urlencoded").formParam("Action", "ConfirmSubscription")
                .formParam("TopicArn", topicArn).formParam("Token", "signed-" + suffix).when().post("/");

        query(DEFAULT_ACCOUNT, "DeleteTopic", "TopicArn", topicArn);

        List<JsonNode> records = snsRecords(DEFAULT_ACCOUNT, logs);
        List<JsonNode> unsubscriptions = records.stream()
                .filter(r -> "Unsubscribe".equals(r.path("eventName").asText())
                        && r.path("requestParameters").path("subscriptionArn").asText().startsWith(topicArn))
                .toList();
        assertThat(unsubscriptions, hasSize(1));
        assertThat(unsubscriptions.getFirst().path("requestParameters").path("subscriptionArn").asText(),
                equalTo(signed));
        List<JsonNode> confirmations = records.stream()
                .filter(r -> "ConfirmSubscription".equals(r.path("eventName").asText())
                        && topicArn.equals(r.path("requestParameters").path("topicArn").asText()))
                .toList();
        assertThat(confirmations, hasSize(1));
        assertThat(confirmations.getFirst().path("requestParameters").path("token").asText(),
                equalTo("signed-" + suffix));
    }

    @Test
    void snsCallsReachEventHistoryWithoutATrail() {
        String account = account();
        String topic = "ct-history-" + UUID.randomUUID().toString().substring(0, 8);
        try (SnsClient sns = AwsTestClients.create(SnsClient.builder(), account, REGION, baseUri)) {
            sns.createTopic(request -> request.name(topic));
        }

        List<String> events = CloudTrailRequests.invokeCloudTrail(auth(account, "cloudtrail"), "LookupEvents",
                        "{\"LookupAttributes\":[{\"AttributeKey\":\"EventName\",\"AttributeValue\":\"CreateTopic\"}]}")
                .then().statusCode(200).extract().jsonPath().getList("Events.CloudTrailEvent", String.class);
        assertThat(events.stream().filter(event -> event.contains("\"eventSource\":\"sns.amazonaws.com\"")
                && event.contains("\"name\":\"" + topic + "\"")).count(), equalTo(1L));
    }

    private static String account() {
        return "6618" + String.format("%08d", (int) (Math.random() * 100_000_000));
    }

    private static void json(String account, String action, String body) {
        given().port(baseUri.getPort()).header("Authorization", auth(account, REGION.id(), "sns"))
                .header("X-Amz-Target", "SNS_20100331." + action).contentType("application/x-amz-json-1.0")
                .body(body).when().post("/").then().statusCode(200);
    }

    private static void query(String account, String action, String... form) {
        RequestSpecification request = given().port(baseUri.getPort())
                .header("Authorization", auth(account, REGION.id(), "sns"))
                .contentType("application/x-www-form-urlencoded").formParam("Action", action)
                .formParam("Version", "2010-03-31");
        for (int i = 0; i < form.length; i += 2) {
            request = request.formParam(form[i], form[i + 1]);
        }
        request.when().post("/").then().statusCode(200);
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

    /** The SNS records of {@code account}, read from the log files delivered to {@code bucket}. */
    private List<JsonNode> snsRecords(String account, String bucket) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(account, "s3")).stream()
                .filter(record -> "sns.amazonaws.com".equals(record.path("eventSource").asText()))
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
