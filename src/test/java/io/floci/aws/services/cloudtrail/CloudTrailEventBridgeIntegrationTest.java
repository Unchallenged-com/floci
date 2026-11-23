package io.floci.aws.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.aws.core.common.AwsArnUtils;
import io.floci.aws.core.common.AwsRegions;
import io.floci.aws.testing.AwsTestClients;
import io.floci.aws.testing.LambdaCodeFixtures;
import io.floci.aws.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.eventbridge.EventBridgeClient;
import software.amazon.awssdk.services.eventbridge.model.RuleState;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.Message;
import software.amazon.awssdk.services.sqs.model.QueueAttributeName;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;

/**
 * A call a logging trail records reaches the default bus of its account and its record's Region as
 * {@code AWS API Call via CloudTrail}, and a read-only one only the rules in the
 * {@code ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS} state.
 */
@QuarkusTest
class CloudTrailEventBridgeIntegrationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String PATTERN = "{\"source\":[\"%s\"],\"detail-type\":[\"AWS API Call via CloudTrail\"]}";

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void writesReachEnabledRulesAndReadsOnlyRulesThatAskForThem() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        Region region = Region.US_EAST_1;
        try (SqsClient sqs = AwsTestClients.create(SqsClient.builder(), account, region);
             EventBridgeClient events = AwsTestClients.create(EventBridgeClient.builder(), account, region);
             LambdaClient lambda = AwsTestClients.create(LambdaClient.builder(), account, region)) {
            String writes = queue(sqs, "ct-writes-" + suffix);
            String all = queue(sqs, "ct-all-" + suffix);
            rule(events, sqs, "ct-writes-" + suffix, "aws.lambda", RuleState.ENABLED, writes);
            rule(events, sqs, "ct-all-" + suffix, "aws.lambda",
                    RuleState.ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS, all);
            String name = "ct-fn-" + suffix;
            lambda.listFunctions();
            assertThat(receive(sqs, writes, 0, 1), hasSize(0));

            startTrail(account, region, "ct-" + suffix);
            createFunction(lambda, account, region, name);
            lambda.getFunction(request -> request.functionName(name));

            List<JsonNode> written = receive(sqs, writes, 1, 5);
            assertThat(written, hasSize(1));
            JsonNode event = written.getFirst();
            assertThat(event.path("version").asText(), equalTo("0"));
            assertThat(event.path("source").asText(), equalTo("aws.lambda"));
            assertThat(event.path("detail-type").asText(), equalTo("AWS API Call via CloudTrail"));
            assertThat(event.path("account").asText(), equalTo(account));
            assertThat(event.path("region").asText(), equalTo(region.id()));
            assertThat(event.path("resources").isArray() && event.path("resources").isEmpty(), equalTo(true));
            assertThat(event.path("detail").path("eventName").asText(), equalTo("CreateFunction20150331"));
            assertThat(event.path("detail").path("eventSource").asText(), equalTo("lambda.amazonaws.com"));
            assertThat(event.path("detail").path("recipientAccountId").asText(), equalTo(account));

            List<String> names = new ArrayList<>();
            for (JsonNode delivered : receive(sqs, all, 2, 5)) {
                names.add(delivered.path("detail").path("eventName").asText());
            }
            assertThat(names, containsInAnyOrder("CreateFunction20150331", "GetFunction20150331v2"));
        }
    }

    @Test
    void aGlobalServicesCallReachesTheBusOfTheRegionItIsRecordedIn() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        Region recorded = Region.US_EAST_1;
        Region other = Region.EU_WEST_1;
        try (SqsClient sqs = AwsTestClients.create(SqsClient.builder(), account, recorded);
             SqsClient otherSqs = AwsTestClients.create(SqsClient.builder(), account, other);
             EventBridgeClient events = AwsTestClients.create(EventBridgeClient.builder(), account, recorded);
             EventBridgeClient otherEvents = AwsTestClients.create(EventBridgeClient.builder(), account, other);
             IamClient iam = AwsTestClients.create(IamClient.builder(), account, other)) {
            String here = queue(sqs, "ct-iam-" + suffix);
            String there = queue(otherSqs, "ct-iam-" + suffix);
            rule(events, sqs, "ct-iam-" + suffix, "aws.iam", RuleState.ENABLED, here);
            rule(otherEvents, otherSqs, "ct-iam-" + suffix, "aws.iam", RuleState.ENABLED, there);
            startTrail(account, recorded, "ct-" + suffix);

            iam.createUser(request -> request.userName("ct-user-" + suffix));

            List<JsonNode> delivered = receive(sqs, here, 1, 5);
            assertThat(delivered, hasSize(1));
            assertThat(delivered.getFirst().path("region").asText(), equalTo(recorded.id()));
            assertThat(delivered.getFirst().path("detail").path("eventName").asText(), equalTo("CreateUser"));
            assertThat(receive(otherSqs, there, 0, 1), hasSize(0));
        }
    }

    private static String account() {
        return "6615" + String.format("%08d", (int) (Math.random() * 100_000_000));
    }

    private static void startTrail(String account, Region region, String name) {
        try (S3Client s3 = AwsTestClients.create(S3Client.builder().forcePathStyle(true), account, region)) {
            s3.createBucket(request -> request.bucket(name + "-logs"));
        }
        cloudTrail(account, region, "CreateTrail", "{\"Name\":\"" + name + "\",\"S3BucketName\":\"" + name
                + "-logs\"}");
        cloudTrail(account, region, "StartLogging", "{\"Name\":\"" + name + "\"}");
    }

    private static void cloudTrail(String account, Region region, String action, String body) {
        given().header("Authorization", auth(account, region.id(), "cloudtrail"))
                .header("X-Amz-Target", "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101." + action)
                .contentType("application/x-amz-json-1.1")
                .body(body)
                .when().post("/")
                .then().statusCode(200);
    }

    private static void createFunction(LambdaClient lambda, String account, Region region, String name)
            throws IOException {
        byte[] archive = LambdaCodeFixtures.nodeJsZip("exports.handler = async () => 'ok';");
        String role = AwsArnUtils.Arn.global(AwsRegions.partitionFor(region.id()), "iam", account, "role/ct")
                .toString();
        lambda.createFunction(request -> request.functionName(name).runtime("nodejs22.x").handler("index.handler")
                .role(role).code(code -> code.zipFile(SdkBytes.fromByteArray(archive))));
    }

    private static String queue(SqsClient sqs, String name) {
        return sqs.createQueue(request -> request.queueName(name)).queueUrl();
    }

    private static void rule(EventBridgeClient events, SqsClient sqs, String name, String source, RuleState state,
                             String queueUrl) {
        String queueArn = sqs.getQueueAttributes(request -> request.queueUrl(queueUrl)
                .attributeNames(QueueAttributeName.QUEUE_ARN)).attributes().get(QueueAttributeName.QUEUE_ARN);
        events.putRule(request -> request.name(name).eventPattern(PATTERN.formatted(source)).state(state));
        events.putTargets(request -> request.rule(name).targets(target -> target.id("queue").arn(queueArn)));
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
