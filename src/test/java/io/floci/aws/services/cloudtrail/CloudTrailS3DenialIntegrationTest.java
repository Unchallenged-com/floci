package io.floci.aws.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import io.floci.aws.testing.CloudTrailLogFiles;
import io.floci.aws.testing.CloudTrailRequests;
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

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;

/**
 * An S3 request IAM enforcement refuses is recorded once, under the event the request names, in
 * the category S3 gives that event.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class CloudTrailS3DenialIntegrationTest {

    private static final String ACCOUNT = "661100000232";

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
    void refusedBucketCallsAreRecordedUnderTheirOwnEvents() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String bucket = "ct-deny-" + suffix;
        String logs = "ct-deny-logs-" + suffix;
        for (String name : List.of(bucket, logs)) {
            given().port(baseUri.getPort()).header("Authorization", auth(ACCOUNT, "s3"))
                    .when().put("/" + name).then().statusCode(200);
            cleanup.register(() -> EnforcementFixtures.removeBucket(baseUri.getPort(), auth(ACCOUNT, "s3"), name));
        }
        String trail = "ct-deny-" + suffix;
        cloudTrail("CreateTrail", "{\"Name\":\"" + trail + "\",\"S3BucketName\":\"" + logs + "\"}");
        cleanup.register(() -> cloudTrail("DeleteTrail", "{\"Name\":\"" + trail + "\"}"));
        cloudTrail("PutEventSelectors", "{\"TrailName\":\"" + trail + "\",\"EventSelectors\":[{\"ReadWriteType\":"
                + "\"All\",\"IncludeManagementEvents\":true,\"DataResources\":[{\"Type\":\"AWS::S3::Object\","
                + "\"Values\":[\"arn:aws:s3:::" + bucket + "/\"]}]}]}");
        cloudTrail("StartLogging", "{\"Name\":\"" + trail + "\"}");
        String user = "ct-deny-user-" + suffix;
        String key = EnforcementFixtures.createUser(cleanup, baseUri.getPort(), auth(ACCOUNT, "iam"), user)
                .accessKeyId();

        given().port(baseUri.getPort()).header("Authorization", auth(key, "s3"))
                .body("<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>")
                .when().put("/" + bucket + "?versioning").then().statusCode(403);
        given().port(baseUri.getPort()).header("Authorization", auth(key, "s3"))
                .when().head("/" + bucket).then().statusCode(403);

        writer.flushNow();
        List<JsonNode> records = CloudTrailLogFiles.records(logs, auth(ACCOUNT, "s3")).stream()
                .filter(record -> key.equals(record.path("userIdentity").path("accessKeyId").asText()))
                .toList();
        assertThat(records.stream().map(record -> record.path("eventName").asText()).toList(),
                contains("PutBucketVersioning", "HeadBucket"));
        assertThat(records.get(0).path("eventCategory").asText(), equalTo("Management"));
        assertThat(records.get(0).path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(records.get(0).path("errorMessage").asText(), startsWith("User: arn:aws:iam::" + ACCOUNT + ":"));
        assertThat(records.get(0).path("errorMessage").asText(),
                containsString("is not authorized to perform: s3:PutBucketVersioning"));
        assertThat(records.get(1).path("eventCategory").asText(), equalTo("Data"));
        assertThat(records.get(1).path("errorCode").asText(), equalTo("AccessDenied"));
    }

    private static void cloudTrail(String action, String body) {
        CloudTrailRequests.invokeCloudTrail(auth(ACCOUNT, "cloudtrail"), action, body).then().statusCode(200);
    }
}
