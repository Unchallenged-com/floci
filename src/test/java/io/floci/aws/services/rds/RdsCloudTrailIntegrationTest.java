package io.floci.aws.services.rds;

import com.fasterxml.jackson.databind.JsonNode;
import io.floci.aws.services.cloudtrail.CloudTrailLogWriter;
import io.floci.aws.testing.AwsTestClients;
import io.floci.aws.testing.CloudTrailLogFiles;
import io.floci.aws.testing.CloudTrailRequests;
import io.floci.aws.testing.EnforcementFixtures;
import io.floci.aws.testing.PartitionCleanup;
import io.floci.aws.testing.RdsMockProfile;
import io.floci.aws.testing.RestAssuredJsonUtils;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.rds.RdsClient;
import software.amazon.awssdk.services.rds.model.RdsException;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The RDS calls Floci records reach a trail's log files under their own names, with their members as the model
 * names and types them, the master user password hidden, and the answer's one structure as its own members; a
 * Neptune or DocumentDB call is recorded as an RDS one, and every call reaches the event history without a trail.
 */
@QuarkusTest
@TestProfile(RdsMockProfile.class)
class RdsCloudTrailIntegrationTest {

    private static final Region REGION = Region.US_EAST_1;
    private static final String HIDDEN = "HIDDEN_DUE_TO_SECURITY_REASONS";

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
    void instanceAndSnapshotCallsAreRecordedWithThePasswordHidden() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-rds-logs-" + suffix;
        startTrail(account, "ct-rds-" + suffix, logs);
        String instance = "ct-db-" + suffix;
        String snapshot = instance + "-snap";
        String copy = instance + "-copy";
        String password = "Initial-Secret-" + suffix;
        String reset = "Reset-Secret-" + suffix;

        try (RdsClient rds = AwsTestClients.create(RdsClient.builder(), account, REGION, baseUri)) {
            rds.createDBInstance(request -> request.dbInstanceIdentifier(instance).engine("postgres")
                    .masterUsername("admin").masterUserPassword(password).dbInstanceClass("db.t3.micro")
                    .allocatedStorage(20).enableCloudwatchLogsExports("postgresql"));
            rds.modifyDBInstance(request -> request.dbInstanceIdentifier(instance).publiclyAccessible(true)
                    .masterUserPassword(reset).applyImmediately(true));
            rds.describeDBInstances(request -> request.dbInstanceIdentifier(instance));
            rds.createDBSnapshot(request -> request.dbInstanceIdentifier(instance).dbSnapshotIdentifier(snapshot));
            rds.modifyDBSnapshotAttribute(request -> request.dbSnapshotIdentifier(snapshot).attributeName("restore")
                    .valuesToAdd("all"));
            rds.copyDBSnapshot(request -> request.sourceDBSnapshotIdentifier(snapshot)
                    .targetDBSnapshotIdentifier(copy));
            rds.deleteDBInstance(request -> request.dbInstanceIdentifier(instance).skipFinalSnapshot(true));
            assertThrows(RdsException.class,
                    () -> rds.deleteDBInstance(request -> request.dbInstanceIdentifier(instance + "-missing")
                            .skipFinalSnapshot(true)));
        }

        List<JsonNode> records = rdsRecords(account, logs);
        for (JsonNode record : records) {
            assertThat(record.toString(), not(containsString(password)));
            assertThat(record.toString(), not(containsString(reset)));
        }

        JsonNode create = only(records, "CreateDBInstance");
        assertThat(create.path("eventSource").asText(), equalTo("rds.amazonaws.com"));
        assertThat(create.path("readOnly").asBoolean(true), equalTo(false));
        JsonNode created = create.path("requestParameters");
        assertThat(created.path("dBInstanceIdentifier").asText(), equalTo(instance));
        assertThat(created.path("allocatedStorage").isInt(), equalTo(true));
        assertThat(created.path("masterUsername").asText(), equalTo("admin"));
        assertThat(created.path("masterUserPassword").asText(), equalTo(HIDDEN));
        assertThat(created.path("enableCloudwatchLogsExports").get(0).asText(), equalTo("postgresql"));
        assertThat(create.path("responseElements").path("dBInstanceIdentifier").asText(), equalTo(instance));
        assertThat(create.path("responseElements").path("dBInstanceArn").asText(),
                equalTo("arn:aws:rds:us-east-1:" + account + ":db:" + instance));
        assertThat(create.path("responseElements").has("dBInstance"), equalTo(false));

        JsonNode modify = only(records, "ModifyDBInstance").path("requestParameters");
        assertThat(modify.path("publiclyAccessible").isBoolean(), equalTo(true));
        assertThat(modify.path("publiclyAccessible").asBoolean(), equalTo(true));
        assertThat(modify.path("masterUserPassword").asText(), equalTo(HIDDEN));

        JsonNode describe = only(records, "DescribeDBInstances");
        assertThat(describe.path("readOnly").asBoolean(), equalTo(true));
        assertThat(describe.path("requestParameters").path("dBInstanceIdentifier").asText(), equalTo(instance));
        assertThat(describe.path("responseElements").isNull(), equalTo(true));

        JsonNode shared = only(records, "ModifyDBSnapshotAttribute");
        assertThat(shared.path("requestParameters").path("attributeName").asText(), equalTo("restore"));
        assertThat(shared.path("requestParameters").path("valuesToAdd").get(0).asText(), equalTo("all"));
        JsonNode attributes = shared.path("responseElements");
        assertThat(attributes.path("dBSnapshotIdentifier").asText(), equalTo(snapshot));
        assertThat(attributes.path("dBSnapshotAttributes").get(0).path("attributeName").asText(), equalTo("restore"));
        assertThat(attributes.path("dBSnapshotAttributes").get(0).path("attributeValues").get(0).asText(),
                equalTo("all"));

        JsonNode copied = only(records, "CopyDBSnapshot");
        assertThat(copied.path("requestParameters").path("sourceDBSnapshotIdentifier").asText(), equalTo(snapshot));
        assertThat(copied.path("responseElements").path("dBSnapshotIdentifier").asText(), equalTo(copy));
        assertThat(only(records, "CreateDBSnapshot").path("responseElements").path("dBInstanceIdentifier").asText(),
                equalTo(instance));

        List<JsonNode> deletes = records.stream()
                .filter(record -> "DeleteDBInstance".equals(record.path("eventName").asText())).toList();
        assertThat(deletes, hasSize(2));
        JsonNode deleted = deletes.stream().filter(record -> !record.has("errorCode")).findFirst().orElseThrow();
        assertThat(deleted.path("requestParameters").path("skipFinalSnapshot").asBoolean(), equalTo(true));
        assertThat(deleted.path("responseElements").path("dBInstanceIdentifier").asText(), equalTo(instance));
        JsonNode failed = deletes.stream().filter(record -> record.has("errorCode")).findFirst().orElseThrow();
        assertThat(failed.path("requestParameters").path("dBInstanceIdentifier").asText(),
                equalTo(instance + "-missing"));
        // RDS answers DBInstanceNotFound; the record names the error shape the operation declares.
        assertThat(failed.path("errorCode").asText(), equalTo("DBInstanceNotFoundFault"));
        assertThat(failed.path("errorMessage").asText().isEmpty(), equalTo(false));
        assertThat(failed.path("responseElements").isNull(), equalTo(true));
    }

    @Test
    void neptuneAndDocumentDbCallsAreRecordedAsRdsCalls() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-rds-family-" + suffix;
        startTrail(account, "ct-rds-family-" + suffix, logs);

        query(account, "neptune", "DeleteDBCluster", "DBClusterIdentifier", "ct-neptune-" + suffix);
        query(account, "docdb", "DeleteDBCluster", "DBClusterIdentifier", "ct-docdb-" + suffix);

        List<JsonNode> deletes = rdsRecords(account, logs).stream()
                .filter(record -> "DeleteDBCluster".equals(record.path("eventName").asText())).toList();
        assertThat(deletes, hasSize(2));
        for (String cluster : List.of("ct-neptune-" + suffix, "ct-docdb-" + suffix)) {
            JsonNode record = deletes.stream().filter(r -> cluster.equals(r.path("requestParameters")
                    .path("dBClusterIdentifier").asText())).findFirst().orElseThrow();
            assertThat(record.path("errorCode").asText().isEmpty(), equalTo(false));
        }
    }

    @Test
    void rdsCallsReachEventHistoryWithoutATrail() {
        String account = account();
        String group = "ct-history-" + UUID.randomUUID().toString().substring(0, 8);
        try (RdsClient rds = AwsTestClients.create(RdsClient.builder(), account, REGION, baseUri)) {
            rds.createDBParameterGroup(request -> request.dbParameterGroupName(group)
                    .dbParameterGroupFamily("postgres16").description("history"));
            rds.deleteDBParameterGroup(request -> request.dbParameterGroupName(group));
        }

        List<String> events = CloudTrailRequests.invokeCloudTrail(auth(account, "cloudtrail"), "LookupEvents",
                        "{\"LookupAttributes\":[{\"AttributeKey\":\"EventName\","
                                + "\"AttributeValue\":\"CreateDBParameterGroup\"}]}")
                .then().statusCode(200).extract().jsonPath().getList("Events.CloudTrailEvent", String.class);
        assertThat(events.stream().filter(event -> event.contains("\"eventSource\":\"rds.amazonaws.com\"")
                && event.contains("\"dBParameterGroupName\":\"" + group + "\"")).count(), equalTo(1L));
    }

    private static String account() {
        return "6627" + String.format("%08d", (int) (Math.random() * 100_000_000));
    }

    /** Sends the Query call {@code action}, signed for {@code scope}, whatever it answers. */
    private void query(String account, String scope, String action, String name, String value) {
        given().port(baseUri.getPort()).header("Authorization", auth(account, REGION.id(), scope))
                .contentType("application/x-www-form-urlencoded").formParam("Action", action)
                .formParam("Version", "2014-10-31").formParam(name, value)
                .when().post("/");
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

    /** The RDS records of {@code account}, read from the log files delivered to {@code bucket}. */
    private List<JsonNode> rdsRecords(String account, String bucket) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(account, "s3")).stream()
                .filter(record -> "rds.amazonaws.com".equals(record.path("eventSource").asText()))
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
