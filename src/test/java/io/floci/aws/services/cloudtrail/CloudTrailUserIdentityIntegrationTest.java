package io.floci.aws.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.aws.testing.EnforcementFixtures;
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.zip.GZIPInputStream;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.startsWith;

/**
 * The caller of a recorded request is described as CloudTrail's userIdentity element types it: the
 * account's own credentials as Root, a user's key as IAMUser, a role session as AssumedRole.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class CloudTrailUserIdentityIntegrationTest {

    private static final String ACCOUNT = "661100000233";
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
    void callersAreRecordedAsTheirIdentityType() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String bucket = "ct-who-" + suffix;
        String logs = "ct-who-logs-" + suffix;
        for (String name : List.of(bucket, logs)) {
            s3(ACCOUNT).when().put("/" + name).then().statusCode(200);
            cleanup.register(() -> EnforcementFixtures.removeBucket(baseUri.getPort(), auth(ACCOUNT, "s3"), name));
        }
        String trail = "ct-who-" + suffix;
        cloudTrail("CreateTrail", "{\"Name\":\"" + trail + "\",\"S3BucketName\":\"" + logs + "\"}");
        cleanup.register(() -> cloudTrail("DeleteTrail", "{\"Name\":\"" + trail + "\"}"));
        cloudTrail("PutEventSelectors", "{\"TrailName\":\"" + trail + "\",\"EventSelectors\":[{\"ReadWriteType\":"
                + "\"All\",\"IncludeManagementEvents\":false,\"DataResources\":[{\"Type\":\"AWS::S3::Object\","
                + "\"Values\":[\"arn:aws:s3:::" + bucket + "/\"]}]}]}");
        cloudTrail("StartLogging", "{\"Name\":\"" + trail + "\"}");

        String user = "ct-who-user-" + suffix;
        String userKey = EnforcementFixtures.createUser(cleanup, baseUri.getPort(), auth(ACCOUNT, "iam"), user)
                .accessKeyId();
        String role = "ct-who-role-" + suffix;
        String roleArn = EnforcementFixtures.createRole(cleanup, baseUri.getPort(), ACCOUNT, "/", role, """
                {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}""");
        EnforcementFixtures.Session session = EnforcementFixtures.assumeRole(baseUri.getPort(), ACCOUNT, roleArn);

        s3(ACCOUNT).body("r").when().put("/" + bucket + "/root.txt").then().statusCode(200);
        s3(userKey).body("u").when().put("/" + bucket + "/user.txt").then().statusCode(403);
        s3(session.accessKeyId()).header("X-Amz-Security-Token", session.sessionToken()).body("s")
                .when().put("/" + bucket + "/role.txt").then().statusCode(200);

        JsonNode root = record(logs, "root.txt").path("userIdentity");
        assertThat(root.path("type").asText(), equalTo("Root"));
        assertThat(root.path("principalId").asText(), equalTo(ACCOUNT));
        assertThat(root.path("arn").asText(), equalTo("arn:aws:iam::" + ACCOUNT + ":root"));
        assertThat(root.has("userName"), equalTo(false));

        JsonNode refused = record(logs, "user.txt");
        assertThat(refused.path("userIdentity").path("type").asText(), equalTo("IAMUser"));
        assertThat(refused.path("userIdentity").path("userName").asText(), equalTo(user));
        assertThat(refused.path("errorMessage").asText(),
                startsWith("User: arn:aws:iam::" + ACCOUNT + ":user/" + user + " is not authorized to perform"));

        JsonNode assumed = record(logs, "role.txt").path("userIdentity");
        assertThat(assumed.path("type").asText(), equalTo("AssumedRole"));
        assertThat(assumed.path("arn").asText(),
                equalTo("arn:aws:sts::" + ACCOUNT + ":assumed-role/" + role + "/" + EnforcementFixtures.SESSION_NAME));
        assertThat(assumed.path("principalId").asText(), matchesPattern("AROA\\w+:" + EnforcementFixtures.SESSION_NAME));
        JsonNode issuer = assumed.path("sessionContext").path("sessionIssuer");
        assertThat(issuer.path("type").asText(), equalTo("Role"));
        assertThat(issuer.path("arn").asText(), equalTo(roleArn));
        assertThat(issuer.path("userName").asText(), equalTo(role));
        assertThat(assumed.path("principalId").asText(), startsWith(issuer.path("principalId").asText() + ":"));
        assertThat(assumed.path("sessionContext").path("attributes").path("creationDate").asText(),
                matchesPattern("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z"));
        assertThat(assumed.path("sessionContext").path("attributes").path("mfaAuthenticated").asText(),
                equalTo("false"));
    }

    private RequestSpecification s3(String accessKeyId) {
        return given().port(baseUri.getPort()).header("Authorization", auth(accessKeyId, "s3"));
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
        List<JsonNode> found = new ArrayList<>();
        List<String> files = s3(ACCOUNT).queryParam("list-type", "2").when().get("/" + logs)
                .then().statusCode(200).extract().xmlPath().getList("ListBucketResult.Contents.Key");
        for (String file : files) {
            byte[] gz = s3(ACCOUNT).when().get("/" + logs + "/" + file).then().statusCode(200).extract().asByteArray();
            try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(gz))) {
                for (JsonNode record : MAPPER.readTree(in.readAllBytes()).path("Records")) {
                    if (key.equals(record.path("requestParameters").path("key").asText())) {
                        found.add(record);
                    }
                }
            }
        }
        assertThat(key + " in " + found, found, hasSize(1));
        return found.getFirst();
    }
}
