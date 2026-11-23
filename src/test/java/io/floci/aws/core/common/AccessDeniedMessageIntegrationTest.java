package io.floci.aws.core.common;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.aws.services.cloudtrail.CloudTrailLogWriter;
import io.floci.aws.testing.EnforcementFixtures;
import io.floci.aws.testing.IamEnforcementProfile;
import io.floci.aws.testing.PartitionCleanup;
import io.floci.aws.testing.RestAssuredJsonUtils;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.UUID;
import java.util.zip.GZIPInputStream;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

/**
 * A call IAM enforcement refuses is answered, and recorded in CloudTrail, with AWS's access denied message: the
 * caller named by its own ARN, a user's or a role session's, and the resource as it is, which S3 alone puts in
 * quotes.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class AccessDeniedMessageIntegrationTest {

    private static final String ACCOUNT = "661100000762";
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
    void aRefusedUserIsNamedByItsArnAndAnS3ResourceIsQuoted() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String bucket = "denied-" + suffix;
        String logs = "denied-logs-" + suffix;
        for (String name : List.of(bucket, logs)) {
            given().port(baseUri.getPort()).header("Authorization", auth(ACCOUNT, "s3"))
                    .when().put("/" + name).then().statusCode(200);
            cleanup.register(() -> EnforcementFixtures.removeBucket(baseUri.getPort(), auth(ACCOUNT, "s3"), name));
        }
        String trail = "denied-" + suffix;
        cloudTrail("CreateTrail", "{\"Name\":\"" + trail + "\",\"S3BucketName\":\"" + logs + "\"}");
        cleanup.register(() -> cloudTrail("DeleteTrail", "{\"Name\":\"" + trail + "\"}"));
        cloudTrail("PutEventSelectors", "{\"TrailName\":\"" + trail + "\",\"EventSelectors\":[{\"ReadWriteType\":"
                + "\"All\",\"IncludeManagementEvents\":false,\"DataResources\":[{\"Type\":\"AWS::S3::Object\","
                + "\"Values\":[\"arn:aws:s3:::" + bucket + "/\"]}]}]}");
        cloudTrail("StartLogging", "{\"Name\":\"" + trail + "\"}");
        String user = "denied-user-" + suffix;
        String key = EnforcementFixtures.createUser(cleanup, baseUri.getPort(), auth(ACCOUNT, "iam"), user)
                .accessKeyId();
        String expected = "User: arn:aws:iam::" + ACCOUNT + ":user/" + user
                + " is not authorized to perform: s3:PutObject on resource: \"arn:aws:s3:::" + bucket
                + "/denied.txt\" because no identity-based policy allows the s3:PutObject action";

        String message = given().port(baseUri.getPort()).header("Authorization", auth(key, "s3")).body("x")
                .when().put("/" + bucket + "/denied.txt")
                .then().statusCode(403).extract().xmlPath().getString("Error.Message");

        assertThat(message, equalTo(expected));
        assertThat(record(logs, "denied.txt").path("errorMessage").asText(), equalTo(expected));
    }

    @Test
    void anotherServicesResourceIsNotQuoted() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String user = "denied-user-" + suffix;
        String key = EnforcementFixtures.createUser(cleanup, baseUri.getPort(), auth(ACCOUNT, "iam"), user)
                .accessKeyId();
        String function = "denied-fn-" + suffix;

        String message = given().port(baseUri.getPort()).header("Authorization", auth(key, "lambda"))
                .when().get("/2015-03-31/functions/" + function)
                .then().statusCode(403).extract().jsonPath().getString("message");

        assertThat(message, equalTo("User: arn:aws:iam::" + ACCOUNT + ":user/" + user
                + " is not authorized to perform: lambda:GetFunction on resource: arn:aws:lambda:us-east-1:" + ACCOUNT
                + ":function:" + function + " because no identity-based policy allows the lambda:GetFunction action"));
    }

    @Test
    void aRefusedRoleSessionIsNamedByItsSessionArn() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String role = "denied-role-" + suffix;
        String roleArn = EnforcementFixtures.createRole(cleanup, baseUri.getPort(), ACCOUNT, "/", role, """
                {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}""");
        EnforcementFixtures.Session session = EnforcementFixtures.assumeRole(baseUri.getPort(), ACCOUNT, roleArn);
        String function = "denied-fn-" + suffix;

        String message = given().port(baseUri.getPort()).header("Authorization", auth(session.accessKeyId(), "lambda"))
                .header("X-Amz-Security-Token", session.sessionToken())
                .when().get("/2015-03-31/functions/" + function)
                .then().statusCode(403).extract().jsonPath().getString("message");

        assertThat(message, equalTo("User: arn:aws:sts::" + ACCOUNT + ":assumed-role/" + role + "/"
                + EnforcementFixtures.SESSION_NAME + " is not authorized to perform: lambda:GetFunction on resource: "
                + "arn:aws:lambda:us-east-1:" + ACCOUNT + ":function:" + function
                + " because no identity-based policy allows the lambda:GetFunction action"));
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

    private JsonNode record(String logs, String key) throws IOException {
        writer.flushNow();
        List<String> files = given().port(baseUri.getPort()).header("Authorization", auth(ACCOUNT, "s3"))
                .queryParam("list-type", "2").when().get("/" + logs)
                .then().statusCode(200).extract().xmlPath().getList("ListBucketResult.Contents.Key");
        for (String file : files) {
            byte[] gz = given().port(baseUri.getPort()).header("Authorization", auth(ACCOUNT, "s3"))
                    .when().get("/" + logs + "/" + file).then().statusCode(200).extract().asByteArray();
            try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(gz))) {
                for (JsonNode record : MAPPER.readTree(in.readAllBytes()).path("Records")) {
                    if (key.equals(record.path("requestParameters").path("key").asText())) {
                        return record;
                    }
                }
            }
        }
        throw new AssertionError("no record of " + key);
    }
}
