package io.floci.aws.services.dynamodb;

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
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;

/**
 * The DynamoDB and DynamoDB Streams calls the DynamoDB guide lists as control plane events reach a trail's
 * log files as management events, and its data plane calls, such as {@code PutItem} and
 * {@code GetShardIterator}, do not.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class DynamoDbCloudTrailIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String KEY_SCHEMA = "\"AttributeDefinitions\": [{\"AttributeName\": \"pk\", "
            + "\"AttributeType\": \"S\"}], \"KeySchema\": [{\"AttributeName\": \"pk\", \"KeyType\": \"HASH\"}], "
            + "\"BillingMode\": \"PAY_PER_REQUEST\"";

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
    void listedCallsAreRecordedAndItemCallsAreNot() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-ddb-logs-" + suffix;
        String table = "ct-ddb-" + suffix;
        startTrail(account, "ct-ddb-" + suffix, logs);

        dynamoDb(account, "CreateTable", "{\"TableName\": \"" + table + "\", " + KEY_SCHEMA + "}").statusCode(200);
        dynamoDb(account, "DescribeTable", "{\"TableName\": \"" + table + "\"}").statusCode(200);
        dynamoDb(account, "PutItem", "{\"TableName\": \"" + table + "\", \"Item\": {\"pk\": {\"S\": \"a\"}}}")
                .statusCode(200);
        String backupArn = dynamoDb(account, "CreateBackup",
                "{\"TableName\": \"" + table + "\", \"BackupName\": \"nightly\"}")
                .statusCode(200).extract().path("BackupDetails.BackupArn");
        dynamoDb(account, "DeleteBackup", "{\"BackupArn\": \"" + backupArn + "\"}").statusCode(200);
        dynamoDb(account, "DeleteTable", "{\"TableName\": \"" + table + "-missing\"}").statusCode(400);
        dynamoDb(account, "DeleteTable", "{\"TableName\": \"" + table + "\"}").statusCode(200);

        List<JsonNode> records = dynamoDbRecords(account, logs);

        JsonNode created = only(records, "CreateTable", false);
        assertThat(created.path("eventSource").asText(), equalTo("dynamodb.amazonaws.com"));
        assertThat(created.path("apiVersion").asText(), equalTo("2012-08-10"));
        assertThat(created.path("managementEvent").asBoolean(), equalTo(true));
        assertThat(created.path("readOnly").asBoolean(), equalTo(false));
        assertThat(created.path("requestParameters").path("tableName").asText(), equalTo(table));
        assertThat(created.path("requestParameters").path("keySchema").path(0).path("keyType").asText(),
                equalTo("HASH"));
        JsonNode description = created.path("responseElements").path("tableDescription");
        assertThat(description.path("tableName").asText(), equalTo(table));
        // The guide's UpdateTable example writes "creationDateTime": "May 3, 2015 11:34:14 PM".
        assertThat(description.path("creationDateTime").asText(),
                matchesPattern("[A-Z][a-z]{2} \\d{1,2}, \\d{4} \\d{1,2}:\\d{2}:\\d{2} [AP]M"));

        JsonNode described = only(records, "DescribeTable", false);
        assertThat(described.path("readOnly").asBoolean(), equalTo(true));
        assertThat(described.path("requestParameters").path("tableName").asText(), equalTo(table));
        assertThat(described.path("responseElements").isNull(), equalTo(true));

        JsonNode backup = only(records, "CreateBackup", false);
        assertThat(backup.path("requestParameters").path("backupName").asText(), equalTo("nightly"));
        assertThat(backup.path("responseElements").path("backupDetails").path("backupArn").asText(),
                equalTo(backupArn));
        assertThat(only(records, "DeleteBackup", false).path("requestParameters").path("backupArn").asText(),
                equalTo(backupArn));

        JsonNode missing = only(records, "DeleteTable", true);
        assertThat(missing.path("errorCode").asText(), equalTo("ResourceNotFoundException"));
        assertThat(missing.path("errorMessage").asText(), not(emptyOrNullString()));
        assertThat(missing.path("responseElements").isNull(), equalTo(true));
        assertThat(missing.path("requestParameters").path("tableName").asText(), equalTo(table + "-missing"));

        JsonNode deleted = only(records, "DeleteTable", false);
        assertThat(deleted.path("requestParameters").path("tableName").asText(), equalTo(table));
        assertThat(deleted.path("responseElements").path("tableDescription").path("tableName").asText(),
                equalTo(table));

        assertThat(named(records, "PutItem"), hasSize(0));
    }

    @Test
    void streamsListedCallsAreRecordedUnderDynamoDb() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-ddbs-logs-" + suffix;
        String table = "ct-ddbs-" + suffix;
        startTrail(account, "ct-ddbs-" + suffix, logs);

        String streamArn = dynamoDb(account, "CreateTable", "{\"TableName\": \"" + table + "\", " + KEY_SCHEMA
                + ", \"StreamSpecification\": {\"StreamEnabled\": true, \"StreamViewType\": \"NEW_IMAGE\"}}")
                .statusCode(200).extract().path("TableDescription.LatestStreamArn");
        cleanup.register(() -> dynamoDb(account, "DeleteTable", "{\"TableName\": \"" + table + "\"}"));
        streams(account, "ListStreams", "{\"TableName\": \"" + table + "\"}").statusCode(200);
        String shardId = streams(account, "DescribeStream", "{\"StreamArn\": \"" + streamArn + "\"}")
                .statusCode(200).extract().path("StreamDescription.Shards[0].ShardId");
        streams(account, "GetShardIterator", "{\"StreamArn\": \"" + streamArn + "\", \"ShardId\": \"" + shardId
                + "\", \"ShardIteratorType\": \"TRIM_HORIZON\"}").statusCode(200);

        List<JsonNode> records = dynamoDbRecords(account, logs);

        // The guide's GetRecords example records a Streams call with "eventSource": "dynamodb.amazonaws.com".
        JsonNode listed = only(records, "ListStreams", false);
        assertThat(listed.path("readOnly").asBoolean(), equalTo(true));
        assertThat(listed.path("apiVersion").asText(), equalTo("2012-08-10"));
        assertThat(listed.path("requestParameters").path("tableName").asText(), equalTo(table));
        assertThat(listed.path("responseElements").isNull(), equalTo(true));

        JsonNode described = only(records, "DescribeStream", false);
        assertThat(described.path("readOnly").asBoolean(), equalTo(true));
        assertThat(described.path("requestParameters").path("streamArn").asText(), equalTo(streamArn));

        assertThat(named(records, "GetShardIterator"), hasSize(0));
    }

    @Test
    void aCallIamEnforcementRefusesIsRecordedWithoutItsParameters() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-ddbr-logs-" + suffix;
        startTrail(account, "ct-ddbr-" + suffix, logs);
        String user = "ct-user-" + suffix;
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, baseUri.getPort(),
                auth(account, "iam"), user);

        JsonPath answer = dynamoDb(credentials.accessKeyId(), "DeleteTable",
                "{\"TableName\": \"ct-ddbr-" + suffix + "\"}").statusCode(400).extract().jsonPath();
        streams(credentials.accessKeyId(), "ListStreams", "{}").statusCode(400);

        // AWS records a refusal as AccessDenied, with the message the refusal answered with.
        List<JsonNode> records = dynamoDbRecords(account, logs);
        JsonNode refused = only(records, "DeleteTable", true);
        assertThat(refused.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(refused.path("errorMessage").asText(), equalTo(answer.getString("message")));
        assertThat(refused.path("userIdentity").path("userName").asText(), equalTo(user));
        assertThat(refused.path("requestParameters").isNull(), equalTo(true));
        assertThat(only(records, "ListStreams", true).path("errorCode").asText(), equalTo("AccessDenied"));
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

    private ValidatableResponse dynamoDb(String accessKeyId, String action, String body) {
        return call(accessKeyId, "DynamoDB_20120810." + action, body);
    }

    private ValidatableResponse streams(String accessKeyId, String action, String body) {
        return call(accessKeyId, "DynamoDBStreams_20120810." + action, body);
    }

    private ValidatableResponse call(String accessKeyId, String target, String body) {
        return given().port(baseUri.getPort())
                .header("Authorization", auth(accessKeyId, REGION, "dynamodb"))
                .header("X-Amz-Target", target)
                .contentType("application/x-amz-json-1.0")
                .body(body)
                .when().post("/")
                .then();
    }

    /** The DynamoDB records of {@code account}, read from the log files delivered to {@code bucket}. */
    private List<JsonNode> dynamoDbRecords(String account, String bucket) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(account, "s3")).stream()
                .filter(record -> "dynamodb.amazonaws.com".equals(record.path("eventSource").asText()))
                .toList();
    }

    private static List<JsonNode> named(List<JsonNode> records, String eventName) {
        return records.stream().filter(record -> eventName.equals(record.path("eventName").asText())).toList();
    }

    private static JsonNode only(List<JsonNode> records, String eventName, boolean failed) {
        List<JsonNode> found = named(records, eventName).stream()
                .filter(record -> record.has("errorCode") == failed)
                .toList();
        assertThat(eventName + " in " + records, found, hasSize(1));
        return found.getFirst();
    }
}
