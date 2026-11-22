package io.floci.aws.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.aws.testing.RestAssuredJsonUtils;
import io.floci.aws.testutil.S3RequestSigner;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.xml.XmlPath;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.zip.GZIPInputStream;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * An unsigned S3 request is recorded with the anonymous caller CloudTrail names, not as one of the
 * account's identities.
 */
@QuarkusTest
class CloudTrailS3AnonymousIdentityIntegrationTest {

    private static final String CT_TARGET = "CloudTrail_20131101.";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String IAM_AUTH = "AWS4-HMAC-SHA256 Credential=test/20260101/us-east-1/iam/aws4_request, "
            + "SignedHeaders=host, Signature=abc";

    @Inject
    CloudTrailLogWriter writer;

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void anUnsignedRequestIsRecordedAsTheAnonymousAccount() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String sourceBucket = "anon-source-" + suffix;
        String destBucket = "anon-dest-" + suffix;
        startTrail("anon-" + suffix, destBucket, sourceBucket);

        given().body("public").when().put("/" + sourceBucket + "/public.txt").then().statusCode(200);
        given().when().get("/" + sourceBucket + "/public.txt").then().statusCode(200);
        given().when().get("/" + sourceBucket + "/missing.txt").then().statusCode(404);
        writer.flushNow();

        List<JsonNode> records = records(destBucket, sourceBucket);
        JsonNode read = only(records, "GetObject", false);
        JsonNode identity = read.path("userIdentity");
        assertEquals("AWSAccount", identity.path("type").asText(), read.toString());
        assertEquals("", identity.path("principalId").asText(null), read.toString());
        assertEquals("anonymous", identity.path("accountId").asText(), read.toString());
        assertFalse(identity.has("arn"), read.toString());
        assertFalse(identity.has("userName"), read.toString());
        assertFalse(identity.has("accessKeyId"), read.toString());
        assertTrue(read.hasNonNull("sharedEventID"), read.toString());
        assertFalse(read.path("additionalEventData").has("SignatureVersion"), read.toString());
        assertFalse(read.path("additionalEventData").has("AuthenticationMethod"), read.toString());
        assertTrue(read.path("additionalEventData").has("bytesTransferredOut"), read.toString());

        JsonNode missing = only(records, "GetObject", true);
        assertEquals("NoSuchKey", missing.path("errorCode").asText(), missing.toString());
        assertEquals("AWSAccount", missing.path("userIdentity").path("type").asText(), missing.toString());
        assertEquals("ANONYMOUS_PRINCIPAL", missing.path("userIdentity").path("accountId").asText(),
                missing.toString());
        assertFalse(missing.has("sharedEventID"), missing.toString());
    }

    @Test
    void aSignedRequestKeepsItsCallerAndSignature() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String sourceBucket = "signed-source-" + suffix;
        String destBucket = "signed-dest-" + suffix;
        String userName = "signer-" + suffix;
        startTrail("signed-" + suffix, destBucket, sourceBucket);
        given().formParam("Action", "CreateUser").formParam("UserName", userName)
                .header("Authorization", IAM_AUTH).when().post("/").then().statusCode(200);
        XmlPath key = given().formParam("Action", "CreateAccessKey").formParam("UserName", userName)
                .header("Authorization", IAM_AUTH).when().post("/").then().statusCode(200).extract().xmlPath();
        String keyId = key.getString("CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.AccessKeyId");
        String secret = key.getString("CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.SecretAccessKey");

        given().filter(S3RequestSigner.signedAs(keyId, secret)).body("signed")
                .when().put("/" + sourceBucket + "/signed.txt").then().statusCode(200);
        writer.flushNow();

        JsonNode put = only(records(destBucket, sourceBucket), "PutObject", false);
        assertEquals("IAMUser", put.path("userIdentity").path("type").asText(), put.toString());
        assertEquals(userName, put.path("userIdentity").path("userName").asText(), put.toString());
        assertEquals("SigV4", put.path("additionalEventData").path("SignatureVersion").asText(), put.toString());
        assertFalse(put.has("sharedEventID"), put.toString());
    }

    private static void startTrail(String trailName, String destBucket, String sourceBucket) {
        given().when().put("/" + sourceBucket).then().statusCode(200);
        given().when().put("/" + destBucket).then().statusCode(200);
        cloudTrail("CreateTrail", "{\"Name\":\"" + trailName + "\",\"S3BucketName\":\"" + destBucket + "\"}");
        cloudTrail("PutEventSelectors", "{\"TrailName\":\"" + trailName + "\",\"EventSelectors\":[{\"ReadWriteType\":"
                + "\"All\",\"DataResources\":[{\"Type\":\"AWS::S3::Object\",\"Values\":[\"arn:aws:s3:::"
                + sourceBucket + "/\"]}]}]}");
        cloudTrail("StartLogging", "{\"Name\":\"" + trailName + "\"}");
    }

    private static void cloudTrail(String action, String body) {
        given().header("X-Amz-Target", CT_TARGET + action).contentType("application/x-amz-json-1.1").body(body)
                .when().post("/").then().statusCode(200);
    }

    /** The records delivered to {@code destBucket} for requests on {@code sourceBucket}. */
    private static List<JsonNode> records(String destBucket, String sourceBucket) throws Exception {
        String listing = given().when().get("/" + destBucket + "?list-type=2").then().statusCode(200)
                .extract().asString();
        List<JsonNode> records = new ArrayList<>();
        for (String logKey : XmlPath.from(listing).getList("ListBucketResult.Contents.Key", String.class)) {
            byte[] gz = given().when().get("/" + destBucket + "/" + logKey).then().statusCode(200)
                    .extract().asByteArray();
            try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(gz))) {
                for (JsonNode record : MAPPER.readTree(in.readAllBytes()).path("Records")) {
                    if (sourceBucket.equals(record.path("requestParameters").path("bucketName").asText())) {
                        records.add(record);
                    }
                }
            }
        }
        return records;
    }

    private static JsonNode only(List<JsonNode> records, String eventName, boolean failed) {
        List<JsonNode> found = records.stream()
                .filter(record -> eventName.equals(record.path("eventName").asText()))
                .filter(record -> record.has("errorCode") == failed)
                .toList();
        assertEquals(1, found.size(), eventName + " in " + records);
        return found.getFirst();
    }
}
