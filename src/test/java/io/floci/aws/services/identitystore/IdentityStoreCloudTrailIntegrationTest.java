package io.floci.aws.services.identitystore;

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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;

/**
 * The Identity Store's public operations reach a trail as management events under
 * {@code identitystore.amazonaws.com}, with the user's and the group's names and attributes hidden, whether the
 * Identity Store ran them, refused them, or IAM enforcement refused them first.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class IdentityStoreCloudTrailIntegrationTest {

    private static final String ROOT = "test";
    private static final String REGION = "us-east-1";
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
    void usersGroupsAndMembershipsAreRecordedWithTheirNamesHidden() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-identitystore-logs-" + suffix;
        startTrail("ct-identitystore-" + suffix, logs);
        String store = identityStoreId();

        String userId = identityStore(ROOT, "CreateUser", """
                {"IdentityStoreId": "%s", "UserName": "ct-user-%s", "DisplayName": "Ct User %s",
                 "Name": {"GivenName": "Ct%s", "FamilyName": "User"},
                 "Emails": [{"Value": "ct-%s@example.com", "Type": "work", "Primary": true}]}"""
                .formatted(store, suffix, suffix, suffix, suffix)).statusCode(200).extract().path("UserId");
        cleanup.register(() -> identityStore(ROOT, "DeleteUser",
                "{\"IdentityStoreId\": \"" + store + "\", \"UserId\": \"" + userId + "\"}"));
        String groupId = identityStore(ROOT, "CreateGroup", """
                {"IdentityStoreId": "%s", "DisplayName": "ct-group-%s", "Description": "Ct group %s"}"""
                .formatted(store, suffix, suffix)).statusCode(200).extract().path("GroupId");
        cleanup.register(() -> identityStore(ROOT, "DeleteGroup",
                "{\"IdentityStoreId\": \"" + store + "\", \"GroupId\": \"" + groupId + "\"}"));
        String membershipId = identityStore(ROOT, "CreateGroupMembership", """
                {"IdentityStoreId": "%s", "GroupId": "%s", "MemberId": {"UserId": "%s"}}"""
                .formatted(store, groupId, userId)).statusCode(200).extract().path("MembershipId");
        cleanup.register(() -> identityStore(ROOT, "DeleteGroupMembership",
                "{\"IdentityStoreId\": \"" + store + "\", \"MembershipId\": \"" + membershipId + "\"}"));
        identityStore(ROOT, "UpdateGroup", """
                {"IdentityStoreId": "%s", "GroupId": "%s",
                 "Operations": [{"AttributePath": "description", "AttributeValue": "Ct renamed %s"}]}"""
                .formatted(store, groupId, suffix)).statusCode(200);
        identityStore(ROOT, "DescribeUser", "{\"IdentityStoreId\": \"" + store + "\", \"UserId\": \"" + userId + "\"}")
                .statusCode(200);
        identityStore(ROOT, "DescribeGroup",
                "{\"IdentityStoreId\": \"" + store + "\", \"GroupId\": \"" + userId + "\"}").statusCode(400);

        List<JsonNode> records = identityStoreRecords(logs, userId, groupId);
        // The names and attributes the calls carried are nowhere in their records.
        assertThat(records.toString(), not(containsString(suffix)));

        JsonNode user = only(records, "CreateUser");
        assertThat(user.path("eventSource").asText(), equalTo("identitystore.amazonaws.com"));
        assertThat(user.path("eventCategory").asText(), equalTo("Management"));
        assertThat(user.path("readOnly").asBoolean(), equalTo(false));
        assertThat(user.path("awsRegion").asText(), equalTo(REGION));
        JsonNode request = user.path("requestParameters");
        assertThat(request.path("identityStoreId").asText(), equalTo(store));
        assertThat(request.path("userName").asText(), equalTo(HIDDEN));
        assertThat(request.path("displayName").asText(), equalTo(HIDDEN));
        assertThat(request.path("name").path("givenName").asText(), equalTo(HIDDEN));
        assertThat(request.path("emails").path(0).path("value").asText(), equalTo(HIDDEN));
        assertThat(request.path("emails").path(0).path("primary").asBoolean(), equalTo(true));
        assertThat(user.path("responseElements").path("userId").asText(), equalTo(userId));
        assertThat(user.path("responseElements").path("identityStoreId").asText(), equalTo(store));

        JsonNode group = only(records, "CreateGroup");
        assertThat(group.path("requestParameters").path("displayName").asText(), equalTo(HIDDEN));
        assertThat(group.path("requestParameters").path("description").asText(), equalTo(HIDDEN));
        assertThat(group.path("responseElements").path("groupId").asText(), equalTo(groupId));

        JsonNode membership = only(records, "CreateGroupMembership");
        assertThat(membership.path("requestParameters").path("groupId").asText(), equalTo(groupId));
        assertThat(membership.path("requestParameters").path("memberId").path("userId").asText(), equalTo(userId));
        assertThat(membership.path("responseElements").path("membershipId").asText(), equalTo(membershipId));

        JsonNode updated = only(records, "UpdateGroup");
        JsonNode operation = updated.path("requestParameters").path("operations").path(0);
        assertThat(operation.path("attributePath").asText(), equalTo("description"));
        assertThat(operation.path("attributeValue").asText(), equalTo(HIDDEN));
        assertThat(updated.path("responseElements").isNull(), equalTo(true));

        JsonNode described = only(records, "DescribeUser");
        assertThat(described.path("readOnly").asBoolean(), equalTo(true));
        assertThat(described.path("requestParameters").path("userId").asText(), equalTo(userId));
        assertThat(described.path("responseElements").isNull(), equalTo(true));

        JsonNode missing = only(records, "DescribeGroup");
        assertThat(missing.path("errorCode").asText(), equalTo("ResourceNotFoundException"));
        assertThat(missing.path("errorMessage").asText(), not(emptyOrNullString()));
        assertThat(missing.path("responseElements").isNull(), equalTo(true));
    }

    @Test
    void aCallIamEnforcementRefusesIsRecordedWithoutItsParameters() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-identitystore-logs-" + suffix;
        startTrail("ct-identitystore-" + suffix, logs);
        String user = "ct-idstore-user-" + suffix;
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, baseUri.getPort(), auth(ROOT, "iam"),
                user);

        JsonPath answer = identityStore(credentials.accessKeyId(), "CreateGroup",
                "{\"IdentityStoreId\": \"" + identityStoreId() + "\", \"DisplayName\": \"ct-refused-" + suffix + "\"}")
                .statusCode(400).extract().jsonPath();

        JsonNode refused = only(identityStoreRecords(logs, credentials.accessKeyId()), "CreateGroup");
        assertThat(refused.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(refused.path("errorMessage").asText(), equalTo(answer.getString("message")));
        assertThat(refused.path("errorMessage").asText(), containsString("identitystore:CreateGroup"));
        assertThat(refused.path("userIdentity").path("userName").asText(), equalTo(user));
        assertThat(refused.path("requestParameters").isNull(), equalTo(true));
        assertThat(refused.path("responseElements").isNull(), equalTo(true));
    }

    private String identityStoreId() {
        return given().port(baseUri.getPort())
                .header("Authorization", auth(ROOT, REGION, "sso"))
                .header("X-Amz-Target", "SWBExternalService.ListInstances")
                .contentType("application/x-amz-json-1.1")
                .body("{}")
                .when().post("/")
                .then().statusCode(200).extract().path("Instances[0].IdentityStoreId");
    }

    private void startTrail(String trail, String bucket) {
        given().port(baseUri.getPort()).header("Authorization", auth(ROOT, "s3"))
                .when().put("/" + bucket).then().statusCode(200);
        cleanup.register(() -> EnforcementFixtures.removeBucket(baseUri.getPort(), auth(ROOT, "s3"), bucket));
        cloudTrail("CreateTrail", "{\"Name\":\"" + trail + "\",\"S3BucketName\":\"" + bucket + "\"}");
        cleanup.register(() -> cloudTrail("DeleteTrail", "{\"Name\":\"" + trail + "\"}"));
        cloudTrail("StartLogging", "{\"Name\":\"" + trail + "\"}");
    }

    private static void cloudTrail(String action, String body) {
        CloudTrailRequests.invokeCloudTrail(auth(ROOT, "cloudtrail"), action, body).then().statusCode(200);
    }

    private ValidatableResponse identityStore(String accessKeyId, String action, String body) {
        return given().port(baseUri.getPort())
                .header("Authorization", auth(accessKeyId, REGION, "identitystore"))
                .header("X-Amz-Target", "AWSIdentityStore." + action)
                .contentType("application/x-amz-json-1.1")
                .body(body)
                .when().post("/")
                .then();
    }

    /**
     * The identitystore.amazonaws.com records that name one of {@code markers}, read from the log files delivered
     * to {@code bucket}.
     */
    private List<JsonNode> identityStoreRecords(String bucket, String... markers) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(ROOT, "s3")).stream()
                .filter(record -> "identitystore.amazonaws.com".equals(record.path("eventSource").asText())
                        && List.of(markers).stream().anyMatch(marker -> record.toString().contains(marker)))
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
