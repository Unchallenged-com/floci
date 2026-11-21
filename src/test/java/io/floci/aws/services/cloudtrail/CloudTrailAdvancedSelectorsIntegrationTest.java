package io.floci.aws.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.aws.testing.RestAssuredJsonUtils;
import io.floci.aws.testutil.S3RequestSigner;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.xml.XmlPath;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.zip.GZIPInputStream;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end coverage for AdvancedEventSelectors: the trail's S3 data-event capture decision
 * must be driven by the advanced selector, not the basic one, once advanced selectors are set.
 * This is the reproduction case for the CloudTrail circular-logging cost problem: excluding the
 * trail's own destination bucket via {@code resources.ARN notStartsWith} stops the trail from
 * recording its own delivery writes.
 *
 * <p>Delivery is driven explicitly through {@link CloudTrailLogWriter#flushNow()} rather than by
 * the background flush, which the configured {@code cloudtrail.flush-interval-seconds} of an hour
 * keeps out of the way. Every bucket and trail name here carries a random suffix and the
 * assertions match on those names, so the class does not need an application of its own.
 */
@QuarkusTest
class CloudTrailAdvancedSelectorsIntegrationTest {

    private static final String CT_TARGET = "CloudTrail_20131101.";
    private static final String JSON11 = "application/x-amz-json-1.1";
    private static final String IAM_AUTH = "AWS4-HMAC-SHA256 Credential=test/20260101/us-east-1/iam/aws4_request, "
            + "SignedHeaders=host, Signature=abc";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Inject
    CloudTrailLogWriter writer;

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void advancedSelectorsExcludeLogBucketButCaptureOthers() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logBucket = "log-bucket-" + suffix;
        String otherBucket = "other-bucket-" + suffix;
        String destBucket = "audit-dest-" + suffix;
        String trailName = "adv-" + suffix;

        createBucket(logBucket);
        createBucket(otherBucket);
        createBucket(destBucket);

        invokeCloudTrail("CreateTrail", String.format("""
                {"Name":"%s","S3BucketName":"%s"}
                """, trailName, destBucket))
                .then().statusCode(200);

        String putAdvanced = String.format("""
                {"TrailName":"%s","AdvancedEventSelectors":[
                  {"Name":"exclude-log-bucket","FieldSelectors":[
                    {"Field":"eventCategory","Equals":["Data"]},
                    {"Field":"resources.type","Equals":["AWS::S3::Object"]},
                    {"Field":"resources.ARN","NotStartsWith":["arn:aws:s3:::%s/"]}
                  ]}
                ]}
                """, trailName, logBucket);
        invokeCloudTrail("PutEventSelectors", putAdvanced)
                .then().statusCode(200)
                .body(containsString("AdvancedEventSelectors"));

        invokeCloudTrail("StartLogging", String.format("{\"Name\":\"%s\"}", trailName))
                .then().statusCode(200);

        putObject(logBucket, "some-key", "excluded");
        putObject(otherBucket, "key", "captured");

        writer.flushNow();

        String listingXml = given()
                .when().get("/" + destBucket + "?list-type=2")
                .then().statusCode(200)
                .extract().asString();

        assertTrue(listingXml.contains(".json.gz"),
                "Expected a delivered log file for the captured (other-bucket) event:\n" + listingXml);

        String logKey = extractFirstKey(listingXml);
        byte[] gz = given().when().get("/" + destBucket + "/" + logKey)
                .then().statusCode(200).extract().asByteArray();
        String json = gunzip(gz);

        assertTrue(json.contains(otherBucket), "Expected other-bucket event to be captured:\n" + json);
        assertFalse(json.contains(logBucket), "Expected log-bucket event to be excluded:\n" + json);
    }

    @Test
    void basicSelectorsStillCaptureAllS3DataEvents() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String sourceBucket = "basic-source-" + suffix;
        String destBucket = "basic-dest-" + suffix;
        String trailName = "basic-" + suffix;

        createBucket(sourceBucket);
        createBucket(destBucket);

        invokeCloudTrail("CreateTrail", String.format("""
                {"Name":"%s","S3BucketName":"%s"}
                """, trailName, destBucket))
                .then().statusCode(200);

        String putBasic = String.format("""
                {"TrailName":"%s","EventSelectors":[
                  {"ReadWriteType":"All","DataResources":[
                    {"Type":"AWS::S3::Object","Values":["arn:aws:s3:::%s/"]}
                  ]}
                ]}
                """, trailName, sourceBucket);
        invokeCloudTrail("PutEventSelectors", putBasic)
                .then().statusCode(200)
                .body(containsString("EventSelectors"));

        invokeCloudTrail("StartLogging", String.format("{\"Name\":\"%s\"}", trailName))
                .then().statusCode(200);

        putObject(sourceBucket, "hello.txt", "hello");
        writer.flushNow();

        String listingXml = given()
                .when().get("/" + destBucket + "?list-type=2")
                .then().statusCode(200)
                .extract().asString();
        assertTrue(listingXml.contains(".json.gz"), "Basic selector should still capture events:\n" + listingXml);
    }

    @Test
    void puttingBothBasicAndAdvancedSelectorsErrors() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String destBucket = "both-dest-" + suffix;
        String trailName = "both-" + suffix;

        createBucket(destBucket);
        invokeCloudTrail("CreateTrail", String.format("""
                {"Name":"%s","S3BucketName":"%s"}
                """, trailName, destBucket))
                .then().statusCode(200);

        String putBoth = String.format("""
                {"TrailName":"%s",
                 "EventSelectors":[{"ReadWriteType":"All"}],
                 "AdvancedEventSelectors":[{"Name":"x","FieldSelectors":[
                    {"Field":"eventCategory","Equals":["Data"]}]}]}
                """, trailName);
        invokeCloudTrail("PutEventSelectors", putBoth)
                .then().statusCode(400)
                .body(containsString("InvalidEventSelectorsException"));
    }

    @Test
    void readOnlyFalseRecordsWritesOnly() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String sourceBucket = "ro-source-" + suffix;
        String destBucket = "ro-dest-" + suffix;
        startTrailWithAdvancedSelector("ro-" + suffix, destBucket, sourceBucket, """
                {"Field":"readOnly","Equals":["false"]}""");

        putObject(sourceBucket, "report.txt", "v1");
        getObject(sourceBucket, "report.txt");
        writer.flushNow();

        assertEquals(List.of("PutObject"), eventNames(destBucket, sourceBucket));
    }

    @Test
    void eventNameSelectorRecordsTheNamedEventsOnly() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String sourceBucket = "name-source-" + suffix;
        String destBucket = "name-dest-" + suffix;
        startTrailWithAdvancedSelector("name-" + suffix, destBucket, sourceBucket, """
                {"Field":"eventName","Equals":["PutObject","DeleteObject"]}""");

        putObject(sourceBucket, "report.txt", "v1");
        getObject(sourceBucket, "report.txt");
        given().when().delete("/" + sourceBucket + "/report.txt").then().statusCode(204);
        writer.flushNow();

        List<String> names = eventNames(destBucket, sourceBucket);
        assertTrue(names.contains("PutObject"), "Expected PutObject: " + names);
        assertTrue(names.contains("DeleteObject"), "Expected DeleteObject: " + names);
        assertFalse(names.contains("GetObject"), "GetObject is not selected: " + names);
    }

    @Test
    void userIdentityArnSelectorRecordsThatCallerOnly() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String sourceBucket = "who-source-" + suffix;
        String destBucket = "who-dest-" + suffix;
        String userName = "uploader-" + suffix;
        String[] key = createUserWithKey(userName);
        startTrailWithAdvancedSelector("who-" + suffix, destBucket, sourceBucket, String.format("""
                {"Field":"userIdentity.arn","Equals":["arn:aws:iam::000000000000:user/%s"]}""", userName));

        given().filter(S3RequestSigner.signedAs(key[0], key[1])).body("by the user")
                .when().put("/" + sourceBucket + "/by-user.txt")
                .then().statusCode(200);
        putObject(sourceBucket, "by-someone-else.txt", "by another caller");
        writer.flushNow();

        List<JsonNode> records = records(destBucket, sourceBucket);
        assertEquals(1, records.size(), "Expected the user's call only: " + records);
        assertEquals("by-user.txt", records.get(0).path("requestParameters").path("key").asText());
        assertEquals("arn:aws:iam::000000000000:user/" + userName,
                records.get(0).path("userIdentity").path("arn").asText());
    }

    // --- Helpers ---

    /**
     * Creates {@code sourceBucket} and {@code destBucket}, and starts a trail delivering to the
     * latter whose one advanced selector selects the S3 object data events of {@code sourceBucket}
     * that also match {@code extraFieldSelector}.
     */
    private static void startTrailWithAdvancedSelector(String trailName, String destBucket, String sourceBucket,
                                                       String extraFieldSelector) {
        createBucket(sourceBucket);
        createBucket(destBucket);
        invokeCloudTrail("CreateTrail", String.format("""
                {"Name":"%s","S3BucketName":"%s"}
                """, trailName, destBucket))
                .then().statusCode(200);
        invokeCloudTrail("PutEventSelectors", String.format("""
                {"TrailName":"%s","AdvancedEventSelectors":[
                  {"Name":"selected","FieldSelectors":[
                    {"Field":"eventCategory","Equals":["Data"]},
                    {"Field":"resources.type","Equals":["AWS::S3::Object"]},
                    {"Field":"resources.ARN","StartsWith":["arn:aws:s3:::%s/"]},
                    %s
                  ]}
                ]}
                """, trailName, sourceBucket, extraFieldSelector))
                .then().statusCode(200);
        invokeCloudTrail("StartLogging", String.format("{\"Name\":\"%s\"}", trailName))
                .then().statusCode(200);
    }

    /** The records delivered to {@code destBucket} for requests on {@code sourceBucket}. */
    private static List<JsonNode> records(String destBucket, String sourceBucket) throws Exception {
        String listingXml = given()
                .when().get("/" + destBucket + "?list-type=2")
                .then().statusCode(200)
                .extract().asString();
        List<JsonNode> records = new ArrayList<>();
        for (String logKey : XmlPath.from(listingXml).getList("ListBucketResult.Contents.Key", String.class)) {
            byte[] gz = given().when().get("/" + destBucket + "/" + logKey)
                    .then().statusCode(200).extract().asByteArray();
            for (JsonNode record : MAPPER.readTree(gunzip(gz)).path("Records")) {
                if (sourceBucket.equals(record.path("requestParameters").path("bucketName").asText())) {
                    records.add(record);
                }
            }
        }
        return records;
    }

    private static List<String> eventNames(String destBucket, String sourceBucket) throws Exception {
        List<String> names = new ArrayList<>();
        for (JsonNode record : records(destBucket, sourceBucket)) {
            names.add(record.path("eventName").asText());
        }
        return names;
    }

    /** Creates an IAM user and an access key for it; returns the key's ID and secret. */
    private static String[] createUserWithKey(String userName) {
        given().formParam("Action", "CreateUser").formParam("UserName", userName)
                .header("Authorization", IAM_AUTH)
                .when().post("/")
                .then().statusCode(200);
        XmlPath key = given().formParam("Action", "CreateAccessKey").formParam("UserName", userName)
                .header("Authorization", IAM_AUTH)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath();
        return new String[] {
                key.getString("CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.AccessKeyId"),
                key.getString("CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.SecretAccessKey")};
    }

    private static void getObject(String bucket, String key) {
        given().when().get("/" + bucket + "/" + key).then().statusCode(200);
    }

    private static Response invokeCloudTrail(String action, String body) {
        return given()
                .header("X-Amz-Target", CT_TARGET + action)
                .contentType(JSON11)
                .body(body)
                .when().post("/");
    }

    private static void createBucket(String name) {
        given().when().put("/" + name).then().statusCode(200);
    }

    private static void putObject(String bucket, String key, String body) {
        given().body(body)
                .when().put("/" + bucket + "/" + key)
                .then().statusCode(200);
    }

    private static String extractFirstKey(String xml) {
        int open = xml.indexOf("<Key>");
        if (open < 0) return null;
        int close = xml.indexOf("</Key>", open);
        return xml.substring(open + 5, close);
    }

    private static String gunzip(byte[] gz) throws Exception {
        try (GZIPInputStream gzin = new GZIPInputStream(new ByteArrayInputStream(gz))) {
            return new String(gzin.readAllBytes());
        }
    }
}
