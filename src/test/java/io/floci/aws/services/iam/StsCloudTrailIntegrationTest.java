package io.floci.aws.services.iam;

import com.fasterxml.jackson.databind.JsonNode;
import io.floci.aws.services.cloudtrail.CloudTrailLogWriter;
import io.floci.aws.testing.CloudTrailLogFiles;
import io.floci.aws.testing.EnforcementFixtures;
import io.floci.aws.testing.EnforcementFixtures.UserCredentials;
import io.floci.aws.testing.IamEnforcementProfile;
import io.floci.aws.testing.PartitionCleanup;
import io.floci.aws.testing.QueryRequests;
import io.floci.aws.testing.RestAssuredJsonUtils;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.path.xml.XmlPath;
import io.restassured.response.ValidatableResponse;
import io.restassured.specification.RequestSpecification;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.UUID;
import java.util.function.UnaryOperator;

import static io.floci.aws.testing.CloudTrailRequests.invokeCloudTrail;
import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;

/**
 * STS API calls reach a trail's log files as CloudTrail management events, with the read-only flag
 * and the response elements the IAM User Guide's table gives each, and no secret access key.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class StsCloudTrailIntegrationTest {

    private static final String ACCOUNT = "661100000252";
    private static final String EXPIRATION = "[A-Z][a-z]{2} \\d{1,2}, \\d{4}, \\d{1,2}:\\d{2}:\\d{2} [AP]M";

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
    void stsCallsAreRecordedAsManagementEvents() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-sts-logs-" + suffix;
        startTrail("ct-sts-" + suffix, logs, true);
        String user = "ct-sts-user-" + suffix;
        UserCredentials caller = EnforcementFixtures.createUser(cleanup, baseUri.getPort(), auth(ACCOUNT, "iam"), user);
        EnforcementFixtures.putUserPolicy(baseUri.getPort(), auth(ACCOUNT, "iam"), user, "assume", allowAll());
        String roleArn = EnforcementFixtures.createRole(cleanup, baseUri.getPort(), ACCOUNT, "/", "ct-sts-role-" + suffix,
                trusting("arn:aws:iam::" + ACCOUNT + ":user/" + user), allowAll());
        String closedRoleArn = EnforcementFixtures.createRole(cleanup, baseUri.getPort(), ACCOUNT, "/",
                "ct-sts-closed-" + suffix, trusting("arn:aws:iam::" + ACCOUNT + ":user/nobody"), allowAll());

        XmlPath assumed = sts(caller.accessKeyId(), "AssumeRole", "RoleArn", roleArn,
                "RoleSessionName", "night-" + suffix, "DurationSeconds", "900",
                "Tags.member.1.Key", "team", "Tags.member.1.Value", "ops").statusCode(200).extract().xmlPath();
        String result = "AssumeRoleResponse.AssumeRoleResult.";
        String sessionKey = assumed.getString(result + "Credentials.AccessKeyId");
        String sessionSecret = assumed.getString(result + "Credentials.SecretAccessKey");
        sts(caller.accessKeyId(), "GetCallerIdentity").statusCode(200);
        XmlPath token = sts(caller.accessKeyId(), "GetSessionToken", "DurationSeconds", "900")
                .statusCode(200).extract().xmlPath();
        String tokenSecret = token.getString("GetSessionTokenResponse.GetSessionTokenResult.Credentials.SecretAccessKey");
        sts(caller.accessKeyId(), "AssumeRole", "RoleArn", closedRoleArn, "RoleSessionName", "denied-" + suffix)
                .statusCode(403);
        sts(ACCOUNT, "GetAccessKeyInfo", "AccessKeyId", caller.accessKeyId()).statusCode(200);

        List<JsonNode> records = stsRecords(logs);

        List<JsonNode> assumes = byCaller(records, "AssumeRole", caller.accessKeyId());
        assertThat(assumes.toString(), assumes, hasSize(2));
        JsonNode assumeRole = assumes.stream().filter(r -> !r.has("errorCode")).findFirst().orElseThrow();
        assertThat(assumeRole.path("eventCategory").asText(), equalTo("Management"));
        assertThat(assumeRole.path("managementEvent").asBoolean(), equalTo(true));
        assertThat(assumeRole.path("readOnly").asBoolean(), equalTo(true));
        assertThat(assumeRole.path("awsRegion").asText(), equalTo("us-east-1"));
        assertThat(assumeRole.path("recipientAccountId").asText(), equalTo(ACCOUNT));
        assertThat(assumeRole.path("sourceIPAddress").asText(), equalTo("127.0.0.1"));
        assertThat(assumeRole.path("userAgent").asText(), not(emptyOrNullString()));
        assertThat(assumeRole.path("userIdentity").path("userName").asText(), equalTo(user));
        JsonNode request = assumeRole.path("requestParameters");
        assertThat(request.path("roleArn").asText(), equalTo(roleArn));
        assertThat(request.path("roleSessionName").asText(), equalTo("night-" + suffix));
        assertThat(request.path("durationSeconds").isInt(), equalTo(true));
        assertThat(request.path("durationSeconds").asInt(), equalTo(900));
        assertThat(request.path("tags").get(0).path("key").asText(), equalTo("team"));
        assertThat(request.path("tags").get(0).path("value").asText(), equalTo("ops"));
        JsonNode response = assumeRole.path("responseElements");
        JsonNode credentials = response.path("credentials");
        assertThat(credentials.path("accessKeyId").asText(), equalTo(sessionKey));
        assertThat(credentials.path("sessionToken").asText(), not(emptyOrNullString()));
        assertThat(credentials.path("expiration").asText(), matchesPattern(EXPIRATION));
        assertThat(credentials.has("secretAccessKey"), equalTo(false));
        assertThat(assumeRole.toString().contains(sessionSecret), equalTo(false));
        assertThat(response.path("assumedRoleUser").path("arn").asText(),
                equalTo("arn:aws:sts::" + ACCOUNT + ":assumed-role/ct-sts-role-" + suffix + "/night-" + suffix));
        // The record carries the sizes the call answered, typed as numbers.
        assertThat(response.path("sessionTokenSize").isInt(), equalTo(true));
        assertThat(response.path("sessionTokenSize").asInt(), equalTo(assumed.getInt(result + "SessionTokenSize")));
        assertThat(response.path("sessionTokenUtilization").asInt(),
                equalTo(assumed.getInt(result + "SessionTokenUtilization")));
        assertThat(assumeRole.path("additionalEventData").path("RequestDetails").path("endpointType").asText(),
                equalTo("regional"));
        assertThat(assumeRole.path("additionalEventData").path("RequestDetails").path("awsServingRegion").asText(),
                equalTo("us-east-1"));
        JsonNode resource = assumeRole.path("resources").get(0);
        assertThat(resource.path("type").asText(), equalTo("AWS::IAM::Role"));
        assertThat(resource.path("ARN").asText(), equalTo(roleArn));
        assertThat(resource.path("accountId").asText(), equalTo(ACCOUNT));

        JsonNode refused = assumes.stream().filter(r -> r.has("errorCode")).findFirst().orElseThrow();
        assertThat(refused.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(refused.path("errorMessage").asText(), matchesPattern(".*not authorized to perform: sts:AssumeRole.*"));
        assertThat(refused.path("requestParameters").isNull(), equalTo(true));
        assertThat(refused.path("responseElements").isNull(), equalTo(true));
        assertThat(refused.has("additionalEventData"), equalTo(false));
        assertThat(refused.has("resources"), equalTo(false));

        JsonNode whoAmI = only(records, "GetCallerIdentity", caller.accessKeyId());
        assertThat(whoAmI.path("readOnly").asBoolean(), equalTo(true));
        assertThat(whoAmI.path("requestParameters").isNull(), equalTo(true));
        assertThat(whoAmI.path("responseElements").isNull(), equalTo(true));
        assertThat(whoAmI.path("additionalEventData").path("RequestDetails").path("endpointType").asText(),
                equalTo("regional"));

        JsonNode sessionToken = only(records, "GetSessionToken", caller.accessKeyId());
        assertThat(sessionToken.path("readOnly").asBoolean(), equalTo(false));
        assertThat(sessionToken.path("requestParameters").path("durationSeconds").asInt(), equalTo(900));
        assertThat(sessionToken.path("responseElements").path("credentials").path("expiration").asText(),
                matchesPattern(EXPIRATION));
        assertThat(sessionToken.toString().contains(tokenSecret), equalTo(false));
        assertThat(sessionToken.path("responseElements").has("packedPolicySize"), equalTo(false));
        assertThat(sessionToken.path("responseElements").path("sessionTokenSize").isInt(), equalTo(true));

        JsonNode keyInfo = only(records, "GetAccessKeyInfo", ACCOUNT);
        assertThat(keyInfo.path("readOnly").asBoolean(), equalTo(true));
        assertThat(keyInfo.path("requestParameters").path("accessKeyId").asText(), equalTo(caller.accessKeyId()));
        assertThat(keyInfo.path("responseElements").isNull(), equalTo(true));
    }

    @Test
    void aCallIamEnforcementRefusesIsRecordedAsItsRefusalAnswered() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-sts-logs-" + suffix;
        startTrail("ct-sts-" + suffix, logs, true);
        String user = "ct-sts-denied-" + suffix;
        UserCredentials caller = EnforcementFixtures.createUser(cleanup, baseUri.getPort(), auth(ACCOUNT, "iam"), user);
        String roleArn = EnforcementFixtures.createRole(cleanup, baseUri.getPort(), ACCOUNT, "/", "ct-sts-role-" + suffix,
                trusting("arn:aws:iam::" + ACCOUNT + ":user/" + user), allowAll());
        EnforcementFixtures.putUserPolicy(baseUri.getPort(), auth(ACCOUNT, "iam"), user, "deny",
                "{\"Version\":\"2012-10-17\",\"Statement\":[" + EnforcementFixtures.statement("Deny", "sts:AssumeRole", "*")
                        + "," + EnforcementFixtures.statement("Deny", "sts:GetWebIdentityToken", "*") + "]}");

        XmlPath refusal = sts(caller.accessKeyId(), "AssumeRole", "RoleArn", roleArn, "RoleSessionName", "s-" + suffix)
                .statusCode(403).extract().xmlPath();
        sts(caller.accessKeyId(), "GetWebIdentityToken", "Audience.member.1", "https://api.example.com",
                "SigningAlgorithm", "RS256").statusCode(403);

        List<JsonNode> records = stsRecords(logs);
        JsonNode tokenRefused = only(records, "GetWebIdentityToken", caller.accessKeyId());
        assertThat(tokenRefused.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(tokenRefused.path("readOnly").asBoolean(), equalTo(false));
        assertThat(tokenRefused.path("requestParameters").isNull(), equalTo(true));

        JsonNode refused = only(records, "AssumeRole", caller.accessKeyId());
        assertThat(refused.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(refused.path("errorMessage").asText(), equalTo(refusal.getString("ErrorResponse.Error.Message")));
        assertThat(refused.path("requestID").asText(), equalTo(refusal.getString("ErrorResponse.RequestId")));
        assertThat(refused.path("readOnly").asBoolean(), equalTo(true));
        assertThat(refused.path("requestParameters").isNull(), equalTo(true));
        assertThat(refused.path("responseElements").isNull(), equalTo(true));
    }

    /**
     * A call to the global endpoint is a global service event, recorded in {@code us-east-1} and only by a trail
     * including global service events; a call to a Regional endpoint is recorded in its Region by every trail there.
     */
    @Test
    void onlyACallToTheGlobalEndpointIsAGlobalServiceEvent() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String included = "ct-sts-global-" + suffix;
        startTrail(included, included, true);
        String excluded = "ct-sts-regional-" + suffix;
        startTrail(excluded, excluded, false);
        String user = "ct-sts-endpoint-" + suffix;
        UserCredentials caller = EnforcementFixtures.createUser(cleanup, baseUri.getPort(), auth(ACCOUNT, "iam"), user);
        EnforcementFixtures.putUserPolicy(baseUri.getPort(), auth(ACCOUNT, "iam"), user, "who", allowAll());

        sts(caller.accessKeyId(), "GetCallerIdentity", request -> request.header("Host", "sts.amazonaws.com"))
                .statusCode(200);
        sts(caller.accessKeyId(), "GetAccessKeyInfo", "AccessKeyId", caller.accessKeyId()).statusCode(200);

        JsonNode global = only(stsRecords(included), "GetCallerIdentity", caller.accessKeyId());
        assertThat(global.path("awsRegion").asText(), equalTo("us-east-1"));
        assertThat(global.path("additionalEventData").path("RequestDetails").path("endpointType").asText(),
                equalTo("global"));
        only(stsRecords(included), "GetAccessKeyInfo", caller.accessKeyId());
        assertThat(byCaller(stsRecords(excluded), "GetCallerIdentity", caller.accessKeyId()), hasSize(0));
        only(stsRecords(excluded), "GetAccessKeyInfo", caller.accessKeyId());
    }

    private static String trusting(String principalArn) {
        return "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\""
                + principalArn + "\"},\"Action\":[\"sts:AssumeRole\",\"sts:TagSession\"]}]}";
    }

    private static String allowAll() {
        return "{\"Version\":\"2012-10-17\",\"Statement\":[" + EnforcementFixtures.statement("Allow", "*", "*") + "]}";
    }

    private void startTrail(String trail, String bucket, boolean includeGlobalServiceEvents) {
        given().port(baseUri.getPort()).header("Authorization", auth(ACCOUNT, "s3"))
                .when().put("/" + bucket).then().statusCode(200);
        cleanup.register(() -> EnforcementFixtures.removeBucket(baseUri.getPort(), auth(ACCOUNT, "s3"), bucket));
        cloudTrail("CreateTrail", "{\"Name\":\"" + trail + "\",\"S3BucketName\":\"" + bucket
                + "\",\"IncludeGlobalServiceEvents\":" + includeGlobalServiceEvents + "}");
        cleanup.register(() -> cloudTrail("DeleteTrail", "{\"Name\":\"" + trail + "\"}"));
        cloudTrail("StartLogging", "{\"Name\":\"" + trail + "\"}");
    }

    private void cloudTrail(String action, String body) {
        invokeCloudTrail(auth(ACCOUNT, "cloudtrail"), action, body).then().statusCode(200);
    }

    private ValidatableResponse sts(String accessKeyId, String action, String... params) {
        return sts(accessKeyId, action, UnaryOperator.identity(), params);
    }

    private ValidatableResponse sts(String accessKeyId, String action, UnaryOperator<RequestSpecification> extra,
                                    String... params) {
        return extra.apply(QueryRequests.request(accessKeyId, "sts", action, params)
                .formParam("Version", "2011-06-15")).when().post("/").then();
    }

    /** The STS records the writer delivers to {@code bucket}. */
    private List<JsonNode> stsRecords(String bucket) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(ACCOUNT, "s3")).stream()
                .filter(record -> "sts.amazonaws.com".equals(record.path("eventSource").asText()))
                .toList();
    }

    private static List<JsonNode> byCaller(List<JsonNode> records, String eventName, String accessKeyId) {
        return records.stream()
                .filter(record -> eventName.equals(record.path("eventName").asText()))
                .filter(record -> accessKeyId.equals(record.path("userIdentity").path("accessKeyId").asText()))
                .toList();
    }

    private static JsonNode only(List<JsonNode> records, String eventName, String accessKeyId) {
        List<JsonNode> found = byCaller(records, eventName, accessKeyId);
        assertThat(eventName + " by " + accessKeyId + " in " + records, found, hasSize(1));
        return found.getFirst();
    }
}
