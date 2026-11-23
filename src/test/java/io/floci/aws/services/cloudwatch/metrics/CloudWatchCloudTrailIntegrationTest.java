package io.floci.aws.services.cloudwatch.metrics;

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
import software.amazon.awssdk.services.cloudwatch.CloudWatchClient;
import software.amazon.awssdk.services.cloudwatch.model.CloudWatchException;
import software.amazon.awssdk.services.cloudwatch.model.ComparisonOperator;
import software.amazon.awssdk.services.cloudwatch.model.StateValue;
import software.amazon.awssdk.services.cloudwatch.model.Statistic;

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
 * The CloudWatch management calls Floci records reach a trail's log files under their own names, with their members
 * as the model names and types them, whether they are made over the Query protocol or by an SDK, and the metric calls
 * do not.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class CloudWatchCloudTrailIntegrationTest {

    private static final Region REGION = Region.US_EAST_1;

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
    void alarmAndDashboardCallsAreRecordedOverEveryProtocol() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-cw-logs-" + suffix;
        startTrail(account, "ct-cw-" + suffix, logs);
        String alarm = "ct-alarm-" + suffix;

        try (CloudWatchClient cloudWatch = AwsTestClients.create(CloudWatchClient.builder(), account, REGION,
                baseUri)) {
            cloudWatch.putMetricAlarm(request -> request.alarmName(alarm).namespace("AWS/EC2")
                    .metricName("CPUUtilization").statistic(Statistic.AVERAGE).period(60).evaluationPeriods(3)
                    .threshold(80.0).comparisonOperator(ComparisonOperator.GREATER_THAN_THRESHOLD)
                    .dimensions(dimension -> dimension.name("InstanceId").value("i-0123456789abcdef0")));
            cloudWatch.describeAlarms(request -> request.alarmNames(alarm));
            cloudWatch.setAlarmState(request -> request.alarmName(alarm).stateValue(StateValue.OK)
                    .stateReason("silenced"));
            assertThrows(CloudWatchException.class, () -> cloudWatch.setAlarmState(request -> request
                    .alarmName(alarm + "-missing").stateValue(StateValue.OK).stateReason("x")));
            cloudWatch.putDashboard(request -> request.dashboardName("ct-dash-" + suffix)
                    .dashboardBody("{\"widgets\":[]}"));
            cloudWatch.putMetricData(request -> request.namespace("CT/Test")
                    .metricData(datum -> datum.metricName("m").value(1.0)));
        }
        query(account, "DisableAlarmActions", "AlarmNames.member.1", alarm);
        query(account, "DeleteAlarms", "AlarmNames.member.1", alarm);

        List<JsonNode> records = cloudWatchRecords(account, logs);

        JsonNode put = only(records, "PutMetricAlarm");
        assertThat(put.path("eventSource").asText(), equalTo("monitoring.amazonaws.com"));
        assertThat(put.path("readOnly").asBoolean(true), equalTo(false));
        JsonNode parameters = put.path("requestParameters");
        assertThat(parameters.path("alarmName").asText(), equalTo(alarm));
        assertThat(parameters.path("threshold").isNumber(), equalTo(true));
        assertThat(parameters.path("period").asInt(), equalTo(60));
        assertThat(parameters.path("dimensions").get(0).path("name").asText(), equalTo("InstanceId"));
        assertThat(put.path("responseElements").isNull(), equalTo(true));

        JsonNode describe = only(records, "DescribeAlarms");
        assertThat(describe.path("readOnly").asBoolean(), equalTo(true));
        assertThat(describe.path("requestParameters").path("alarmNames").get(0).asText(), equalTo(alarm));
        assertThat(describe.path("responseElements").isNull(), equalTo(true));

        List<JsonNode> states = records.stream().filter(r -> "SetAlarmState".equals(r.path("eventName").asText()))
                .toList();
        assertThat(states, hasSize(2));
        JsonNode failed = states.stream().filter(r -> r.has("errorCode")).findFirst().orElseThrow();
        assertThat(failed.path("requestParameters").path("alarmName").asText(), equalTo(alarm + "-missing"));
        JsonNode silenced = states.stream().filter(r -> !r.has("errorCode")).findFirst().orElseThrow();
        assertThat(silenced.path("requestParameters").path("stateValue").asText(), equalTo("OK"));

        assertThat(only(records, "PutDashboard").path("requestParameters").path("dashboardName").asText(),
                equalTo("ct-dash-" + suffix));
        JsonNode disable = only(records, "DisableAlarmActions");
        assertThat(disable.path("requestParameters").path("alarmNames").get(0).asText(), equalTo(alarm));
        assertThat(disable.path("responseElements").isNull(), equalTo(true));
        assertThat(only(records, "DeleteAlarms").path("requestParameters").path("alarmNames").get(0).asText(),
                equalTo(alarm));
        assertThat(records.stream().filter(r -> "PutMetricData".equals(r.path("eventName").asText())).toList(),
                hasSize(0));
    }

    @Test
    void aRefusedCallIsRecordedWithoutItsMembers() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-cw-logs-" + suffix;
        startTrail(account, "ct-cw-" + suffix, logs);
        String user = "ct-cw-user-" + suffix;
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, baseUri.getPort(),
                auth(account, "iam"), user);

        try (CloudWatchClient cloudWatch = AwsTestClients.create(CloudWatchClient.builder(), credentials.accessKeyId(),
                credentials.secretAccessKey(), REGION, baseUri)) {
            CloudWatchException error = assertThrows(CloudWatchException.class,
                    () -> cloudWatch.deleteAlarms(request -> request.alarmNames("ct-alarm-" + suffix)));
            assertThat(error.statusCode() >= 400, equalTo(true));
        }

        JsonNode refused = only(cloudWatchRecords(account, logs), "DeleteAlarms");
        assertThat(refused.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(refused.path("userIdentity").path("userName").asText(), equalTo(user));
        assertThat(refused.path("requestParameters").isNull(), equalTo(true));
    }

    private static String account() {
        return "6617" + String.format("%08d", (int) (Math.random() * 100_000_000));
    }

    private void query(String account, String action, String... form) {
        RequestSpecification request = given().port(baseUri.getPort())
                .header("Authorization", auth(account, REGION.id(), "monitoring"))
                .contentType("application/x-www-form-urlencoded").formParam("Action", action)
                .formParam("Version", "2010-08-01");
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

    /** The CloudWatch records of {@code account}, read from the log files delivered to {@code bucket}. */
    private List<JsonNode> cloudWatchRecords(String account, String bucket) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(account, "s3")).stream()
                .filter(record -> "monitoring.amazonaws.com".equals(record.path("eventSource").asText()))
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
