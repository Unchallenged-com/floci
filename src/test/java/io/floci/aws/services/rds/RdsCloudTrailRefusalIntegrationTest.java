package io.floci.aws.services.rds;

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
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * An RDS call IAM enforcement refuses before RDS runs it reaches the trail as {@code AccessDenied}, with the
 * refusal's message and no request members. The call is refused, so no database starts.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class RdsCloudTrailRefusalIntegrationTest {

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
    void aRefusedCallIsRecordedWithoutItsMembers() throws IOException {
        String account = "6637" + String.format("%08d", (int) (Math.random() * 100_000_000));
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-rds-denied-" + suffix;
        startTrail(account, "ct-rds-denied-" + suffix, logs);
        String user = "ct-rds-user-" + suffix;
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, baseUri.getPort(),
                auth(account, "iam"), user);

        try (RdsClient rds = AwsTestClients.create(RdsClient.builder(), credentials.accessKeyId(),
                credentials.secretAccessKey(), REGION, baseUri)) {
            RdsException error = assertThrows(RdsException.class,
                    () -> rds.modifyDBSnapshotAttribute(request -> request.dbSnapshotIdentifier("ct-snap-" + suffix)
                            .attributeName("restore").valuesToAdd("all")));
            assertThat(error.statusCode() >= 400, equalTo(true));
        }

        writer.flushNow();
        List<JsonNode> refused = CloudTrailLogFiles.records(logs, auth(account, "s3")).stream()
                .filter(record -> "rds.amazonaws.com".equals(record.path("eventSource").asText()))
                .toList();
        assertThat(refused, hasSize(1));
        JsonNode record = refused.getFirst();
        assertThat(record.path("eventName").asText(), equalTo("ModifyDBSnapshotAttribute"));
        assertThat(record.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(record.path("errorMessage").asText(), containsString("rds:ModifyDBSnapshotAttribute"));
        assertThat(record.path("userIdentity").path("userName").asText(), equalTo(user));
        assertThat(record.path("requestParameters").isNull(), equalTo(true));
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
}
