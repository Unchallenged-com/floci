package io.floci.aws.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.aws.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.zip.GZIPInputStream;

import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.lessThan;
import static org.hamcrest.Matchers.not;

/**
 * The S3 operations the S3 User Guide lists as CloudTrail events reach a trail's log files under
 * the names and categories it gives them: bucket-level calls as management events, object-level
 * calls, {@code DeleteObjects}, {@code ListObjectVersions} and {@code HeadBucket} as data events.
 */
@QuarkusTest
class CloudTrailS3CoverageIntegrationTest {

    private static final String CT_TARGET = "CloudTrail_20131101.";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Inject
    CloudTrailLogWriter writer;

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void bucketConfigurationChangesAreManagementEvents() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String bucket = "ct-s3-config-" + suffix;
        String logs = startTrail(suffix, bucket);
        given().when().put("/" + bucket).then().statusCode(200);
        given().body("<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
                        + "<Status>Suspended</Status></VersioningConfiguration>")
                .when().put("/" + bucket + "?versioning").then().statusCode(200);
        given().when().get("/" + bucket + "?versioning").then().statusCode(200);
        given().body("<Tagging><TagSet><Tag><Key>owner</Key><Value>it</Value></Tag>"
                        + "<Tag><Key>env</Key><Value>prod</Value></Tag></TagSet></Tagging>")
                .when().put("/" + bucket + "?tagging").then().statusCode(lessThan(300));
        given().body("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\","
                        + "\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::" + bucket + "/*\"}]}")
                .when().put("/" + bucket + "?policy").then().statusCode(lessThan(300));
        given().when().delete("/" + bucket + "?policy").then().statusCode(lessThan(300));
        given().when().delete("/" + bucket).then().statusCode(204);

        List<JsonNode> records = records(logs, bucket);
        assertThat(names(records), contains("CreateBucket", "PutBucketVersioning", "GetBucketVersioning",
                "PutBucketTagging", "PutBucketPolicy", "DeleteBucketPolicy", "DeleteBucket"));
        for (JsonNode record : records) {
            assertThat(record.path("eventCategory").asText(), equalTo("Management"));
            assertThat(record.path("managementEvent").asBoolean(), equalTo(true));
            assertThat(record.path("eventSource").asText(), equalTo("s3.amazonaws.com"));
            assertThat(record.path("readOnly").asBoolean(), equalTo(record.path("eventName").asText().startsWith("Get")));
            assertThat(record.path("requestParameters").path("bucketName").asText(), equalTo(bucket));
            assertThat(record.path("responseElements").isNull(), equalTo(true));
        }
        JsonNode versioning = records.get(1).path("requestParameters");
        assertThat(versioning.has("versioning"), equalTo(true));
        assertThat(versioning.path("VersioningConfiguration").path("Status").asText(), equalTo("Suspended"));
        assertThat(versioning.path("VersioningConfiguration").path("xmlns").asText(),
                equalTo("http://s3.amazonaws.com/doc/2006-03-01/"));
        assertThat(records.get(3).path("requestParameters").path("Tagging").path("TagSet").path("Tag").size(),
                equalTo(2));
        JsonNode policy = records.get(4).path("requestParameters");
        assertThat(policy.path("policy").asText(), equalTo(""));
        assertThat(policy.path("bucketPolicy").path("Statement").get(0).path("Effect").asText(), equalTo("Deny"));
        assertThat(records.get(0).has("resources"), equalTo(false));
        assertThat(records.get(1).path("resources").get(0).path("type").asText(), equalTo("AWS::S3::Bucket"));
        assertThat(records.get(1).path("resources").get(0).path("ARN").asText(), equalTo("arn:aws:s3:::" + bucket));
        assertThat(records.get(1).path("additionalEventData").path("bytesTransferredIn").asLong() > 0,
                equalTo(true));
    }

    @Test
    void objectLevelCallsBeyondTheBasicOnesAreDataEvents() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String bucket = "ct-s3-data-" + suffix;
        given().when().put("/" + bucket).then().statusCode(200);
        String logs = startTrail(suffix, bucket);
        given().body("a").when().put("/" + bucket + "/a.txt").then().statusCode(200);
        given().body("b").when().put("/" + bucket + "/b.txt").then().statusCode(200);
        given().header("x-amz-copy-source", "/" + bucket + "/a.txt")
                .when().put("/" + bucket + "/c.txt").then().statusCode(200);
        given().body("<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>")
                .when().put("/" + bucket + "/a.txt?tagging").then().statusCode(200);
        given().when().head("/" + bucket).then().statusCode(200);
        given().when().get("/" + bucket + "?versions").then().statusCode(200);
        String uploadId = given().when().post("/" + bucket + "/big.bin?uploads")
                .then().statusCode(200).extract().xmlPath().getString("InitiateMultipartUploadResult.UploadId");
        String etag = given().body("part").when().put("/" + bucket + "/big.bin?partNumber=1&uploadId=" + uploadId)
                .then().statusCode(200).extract().header("ETag");
        given().body("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>" + etag
                        + "</ETag></Part></CompleteMultipartUpload>")
                .when().post("/" + bucket + "/big.bin?uploadId=" + uploadId).then().statusCode(200);
        given().body("<Delete><Object><Key>a.txt</Key></Object><Object><Key>b.txt</Key></Object></Delete>")
                .when().post("/" + bucket + "?delete").then().statusCode(200);

        List<JsonNode> records = records(logs, bucket);
        assertThat(names(records), contains("PutObject", "PutObject", "CopyObject", "PutObjectTagging", "HeadBucket",
                "ListObjectVersions", "CreateMultipartUpload", "UploadPart", "CompleteMultipartUpload",
                "DeleteObjects", "DeleteObject", "DeleteObject"));
        for (JsonNode record : records) {
            assertThat(record.path("eventCategory").asText(), equalTo("Data"));
            assertThat(record.path("managementEvent").asBoolean(), equalTo(false));
        }
        JsonNode batch = records.get(9);
        assertThat(batch.path("requestParameters").has("delete"), equalTo(true));
        assertThat(batch.path("readOnly").asBoolean(), equalTo(false));
        List<String> deleted = records.subList(10, 12).stream()
                .map(record -> record.path("requestParameters").path("key").asText()).toList();
        assertThat(deleted, containsInAnyOrder("a.txt", "b.txt"));
        assertThat(records.get(5).path("readOnly").asBoolean(), equalTo(true));
    }

    @Test
    void objectLockCallsAreRecordedWithTheRetentionAndLegalHoldTheyLeave() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String bucket = "ct-s3-lock-" + suffix;
        String logs = startTrail(suffix, bucket);
        given().header("x-amz-bucket-object-lock-enabled", "true")
                .when().put("/" + bucket).then().statusCode(200);
        given().body("x").when().put("/" + bucket + "/held.txt").then().statusCode(200);
        given().body("<LegalHold><Status>ON</Status></LegalHold>")
                .when().put("/" + bucket + "/held.txt?legal-hold").then().statusCode(200);
        given().body("<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2099-01-01T00:00:00Z</RetainUntilDate>"
                        + "</Retention>")
                .when().put("/" + bucket + "/held.txt?retention").then().statusCode(200);
        given().when().get("/" + bucket + "/held.txt?retention").then().statusCode(200);

        List<JsonNode> records = records(logs, bucket);
        assertThat(names(records), contains("CreateBucket", "PutObject", "PutObjectLockLegalHold",
                "PutObjectLockRetention", "GetObjectLockRetention"));
        JsonNode hold = records.get(2).path("additionalEventData").path("objectRetentionInfo");
        assertThat(hold.path("legalHoldInfo").path("isUnderLegalHold").asBoolean(), equalTo(true));
        assertThat(hold.path("legalHoldInfo").path("lastModifiedTime").isNumber(), equalTo(true));
        assertThat(hold.has("retentionInfo"), equalTo(false));
        JsonNode set = records.get(3);
        assertThat(set.path("requestParameters").has("retention"), equalTo(true));
        JsonNode retention = set.path("additionalEventData").path("objectRetentionInfo");
        assertThat(retention.path("retentionInfo").path("retainUntilMode").asText(), equalTo("GOVERNANCE"));
        assertThat(retention.path("retentionInfo").path("retainUntilTime").asLong(), equalTo(4070908800000L));
        assertThat(retention.path("retentionInfo").path("lastModifiedTime").isNumber(), equalTo(true));
        assertThat(retention.path("legalHoldInfo").path("isUnderLegalHold").asBoolean(), equalTo(true));
        JsonNode read = records.get(4).path("additionalEventData").path("objectRetentionInfo");
        assertThat(read.has("retentionInfo"), equalTo(true));
        assertThat(read.has("legalHoldInfo"), equalTo(false));
        assertThat(records.get(4).path("readOnly").asBoolean(), equalTo(true));
        assertThat(records.stream().filter(record -> "PutObjectRetention".equals(record.path("eventName").asText()))
                .toList(), empty());
    }

    private String startTrail(String suffix, String bucket) {
        String logs = "ct-s3-logs-" + suffix;
        String trail = "ct-s3-" + suffix;
        given().when().put("/" + logs).then().statusCode(200);
        cloudTrail("CreateTrail", "{\"Name\":\"" + trail + "\",\"S3BucketName\":\"" + logs + "\"}");
        cloudTrail("PutEventSelectors", "{\"TrailName\":\"" + trail + "\",\"EventSelectors\":[{\"ReadWriteType\":"
                + "\"All\",\"IncludeManagementEvents\":true,\"DataResources\":[{\"Type\":\"AWS::S3::Object\","
                + "\"Values\":[\"arn:aws:s3:::" + bucket + "/\"]}]}]}");
        cloudTrail("StartLogging", "{\"Name\":\"" + trail + "\"}");
        return logs;
    }

    private static void cloudTrail(String action, String body) {
        given().header("X-Amz-Target", CT_TARGET + action).contentType("application/x-amz-json-1.1").body(body)
                .when().post("/").then().statusCode(200);
    }

    /** The records naming {@code bucket}, in the order the trail buffered them, from every delivered file. */
    private List<JsonNode> records(String logs, String bucket) throws IOException {
        writer.flushNow();
        List<String> keys = given().queryParam("list-type", "2").when().get("/" + logs)
                .then().statusCode(200).extract().xmlPath().getList("ListBucketResult.Contents.Key");
        List<JsonNode> records = new ArrayList<>();
        for (String key : keys) {
            byte[] gz = given().when().get("/" + logs + "/" + key).then().statusCode(200).extract().asByteArray();
            try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(gz))) {
                for (JsonNode record : MAPPER.readTree(in.readAllBytes()).path("Records")) {
                    if (bucket.equals(record.path("requestParameters").path("bucketName").asText())) {
                        records.add(record);
                    }
                }
            }
        }
        assertThat(records, not(empty()));
        return records;
    }

    private static List<String> names(List<JsonNode> records) {
        return records.stream().map(record -> record.path("eventName").asText()).toList();
    }
}
