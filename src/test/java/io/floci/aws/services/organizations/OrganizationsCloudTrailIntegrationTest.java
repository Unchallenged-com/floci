package io.floci.aws.services.organizations;

import com.fasterxml.jackson.databind.JsonNode;
import io.floci.aws.services.cloudtrail.CloudTrailLogWriter;
import io.floci.aws.testing.CloudTrailLogFiles;
import io.floci.aws.testing.CloudTrailRequests;
import io.floci.aws.testing.EnforcementFixtures;
import io.floci.aws.testing.EnforcementFixtures.UserCredentials;
import io.floci.aws.testing.IamEnforcementProfile;
import io.floci.aws.testing.OrganizationsRequests;
import io.floci.aws.testing.PartitionCleanup;
import io.floci.aws.testing.RestAssuredJsonUtils;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.path.json.JsonPath;
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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;

/**
 * Organizations calls reach a trail's log files as management events recorded in us-east-1, whatever Region the
 * caller signed for, with their members, their answers, the sensitive members written {@code "****"}, their errors
 * and their refusals.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class OrganizationsCloudTrailIntegrationTest {

    private static final String CALLER_REGION = "eu-west-1";
    private static final String RECORDED_REGION = "us-east-1";
    private static final String EMAIL = "do-not-log-" + UUID.randomUUID() + "@example.com";
    private static final String ACCESS_ROLE = "OrganizationAccountAccessRole";
    private static final String SCP = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\","
            + "\"Action\":\"cloudtrail:StopLogging\",\"Resource\":\"*\"}]}";

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
    void callsAreRecordedInUsEast1WithTheirMembersAndAnswers() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-orgs-logs-" + suffix;
        String regional = "ct-orgs-regional-" + suffix;
        startTrail(account, "ct-orgs-" + suffix, logs, true);
        startTrail(account, "ct-orgs-regional-" + suffix, regional, false);

        createOrganization(account);
        call(account, "DescribeOrganization", "{}", 200);
        String root = call(account, "ListRoots", "{}", 200).getString("Roots[0].Id");
        call(account, "EnablePolicyType", "{\"RootId\":\"" + root + "\",\"PolicyType\":\"SERVICE_CONTROL_POLICY\"}",
                200);
        String unit = call(account, "CreateOrganizationalUnit",
                "{\"ParentId\":\"" + root + "\",\"Name\":\"ct-unit\"}", 200).getString("OrganizationalUnit.Id");
        cleanup.register(() -> quietly(account, "DeleteOrganizationalUnit",
                "{\"OrganizationalUnitId\":\"" + unit + "\"}"));
        String policy = call(account, "CreatePolicy", "{\"Name\":\"ct-scp\",\"Description\":\"no stop\","
                + "\"Type\":\"SERVICE_CONTROL_POLICY\",\"Content\":" + json(SCP) + "}", 200)
                .getString("Policy.PolicySummary.Id");
        cleanup.register(() -> quietly(account, "DeletePolicy", "{\"PolicyId\":\"" + policy + "\"}"));
        call(account, "AttachPolicy", "{\"PolicyId\":\"" + policy + "\",\"TargetId\":\"" + unit + "\"}", 200);
        JsonPath missingTarget = call(account, "AttachPolicy",
                "{\"PolicyId\":\"" + policy + "\",\"TargetId\":\"ou-none-00000000\"}", 400);
        String member = createAccount(account);
        call(account, "DetachPolicy", "{\"PolicyId\":\"" + policy + "\",\"TargetId\":\"" + unit + "\"}", 200);
        call(account, "DeletePolicy", "{\"PolicyId\":\"" + policy + "\"}", 200);
        call(account, "RemoveAccountFromOrganization", "{\"AccountId\":\"" + member + "\"}", 200);
        call(account, "DeleteOrganizationalUnit", "{\"OrganizationalUnitId\":\"" + unit + "\"}", 200);
        call(account, "DeleteOrganization", "{}", 200);

        List<JsonNode> records = organizationsRecords(account, logs);
        assertThat(records.toString(), not(containsString(EMAIL)));
        for (JsonNode record : records) {
            assertThat(record.toString(), record.path("awsRegion").asText(), equalTo(RECORDED_REGION));
            assertThat(record.path("recipientAccountId").asText(), equalTo(account));
        }
        assertThat(organizationsRecords(account, regional), empty());

        JsonNode describe = only(records, "DescribeOrganization");
        assertThat(describe.path("readOnly").asBoolean(), equalTo(true));
        assertThat(describe.path("requestParameters").isNull(), equalTo(true));
        assertThat(describe.path("responseElements").isNull(), equalTo(true));

        JsonNode created = only(records, "CreateOrganization");
        assertThat(created.path("readOnly").asBoolean(true), equalTo(false));
        assertThat(created.path("requestParameters").path("featureSet").asText(), equalTo("ALL"));
        assertThat(created.path("responseElements").path("organization").path("id").asText(),
                matchesPattern("o-[a-z0-9]{10}"));

        JsonNode createdUnit = only(records, "CreateOrganizationalUnit");
        assertThat(createdUnit.path("requestParameters").path("parentId").asText(), equalTo(root));
        assertThat(createdUnit.path("requestParameters").path("name").asText(), equalTo("ct-unit"));
        assertThat(createdUnit.path("responseElements").path("organizationalUnit").path("id").asText(),
                equalTo(unit));

        JsonNode createdPolicy = only(records, "CreatePolicy");
        assertThat(createdPolicy.path("requestParameters").path("type").asText(), equalTo("SERVICE_CONTROL_POLICY"));
        assertThat(createdPolicy.path("requestParameters").path("content").asText(), equalTo(SCP));
        assertThat(createdPolicy.path("responseElements").path("policy").path("policySummary").path("id").asText(),
                equalTo(policy));

        List<JsonNode> attached = named(records, "AttachPolicy");
        assertThat(attached, hasSize(2));
        JsonNode attach = attached.stream().filter(record -> !record.has("errorCode")).findFirst().orElseThrow();
        assertThat(attach.path("requestParameters").path("policyId").asText(), equalTo(policy));
        assertThat(attach.path("requestParameters").path("targetId").asText(), equalTo(unit));
        assertThat(attach.path("responseElements").isNull(), equalTo(true));
        JsonNode failed = attached.stream().filter(record -> record.has("errorCode")).findFirst().orElseThrow();
        assertThat(failed.path("errorCode").asText(), equalTo(missingTarget.getString("__type")));
        assertThat(failed.path("errorMessage").asText(), equalTo(missingTarget.getString("message")));
        assertThat(failed.path("requestParameters").path("targetId").asText(), equalTo("ou-none-00000000"));
        assertThat(failed.path("responseElements").isNull(), equalTo(true));

        JsonNode createdAccount = only(records, "CreateAccount");
        assertThat(createdAccount.path("requestParameters").path("email").asText(), equalTo("****"));
        assertThat(createdAccount.path("requestParameters").path("accountName").asText(), equalTo("****"));
        JsonNode status = createdAccount.path("responseElements").path("createAccountStatus");
        assertThat(status.path("accountName").asText(), equalTo("****"));
        assertThat(status.path("accountId").asText(), equalTo(member));
        assertThat(status.path("requestedTimestamp").asText(),
                matchesPattern("[A-Z][a-z]{2} \\d{1,2}, \\d{4}, \\d{1,2}:\\d{2}:\\d{2} [AP]M"));

        for (String event : List.of("DetachPolicy", "DeletePolicy", "RemoveAccountFromOrganization",
                "DeleteOrganizationalUnit", "DeleteOrganization", "EnablePolicyType")) {
            assertThat(event, only(records, event).path("readOnly").asBoolean(true), equalTo(false));
        }
        assertThat(only(records, "RemoveAccountFromOrganization").path("requestParameters").path("accountId")
                .asText(), equalTo(member));
        assertThat(only(records, "DeleteOrganization").path("responseElements").isNull(), equalTo(true));
        assertThat(only(records, "ListRoots").path("readOnly").asBoolean(), equalTo(true));
    }

    @Test
    void leavingTheOrganizationIsRecordedInTheMembersAccount() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        createOrganization(account);
        String member = createAccount(account);
        String logs = "ct-orgs-member-" + suffix;
        startTrail(member, "ct-orgs-member-" + suffix, logs, true);

        call(member, "LeaveOrganization", "{}", 200);
        call(account, "DeleteOrganization", "{}", 200);

        JsonNode left = only(organizationsRecords(member, logs), "LeaveOrganization");
        assertThat(left.path("awsRegion").asText(), equalTo(RECORDED_REGION));
        assertThat(left.path("recipientAccountId").asText(), equalTo(member));
        assertThat(left.path("readOnly").asBoolean(true), equalTo(false));
        assertThat(left.path("requestParameters").isNull(), equalTo(true));
        assertThat(left.path("responseElements").isNull(), equalTo(true));
    }

    @Test
    void aRefusedCallIsRecordedWithoutItsMembers() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-orgs-refused-" + suffix;
        startTrail(account, "ct-orgs-refused-" + suffix, logs, true);
        String user = "ct-user-" + suffix;
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, baseUri.getPort(),
                auth(account, "iam"), user);

        OrganizationsRequests.request(credentials.accessKeyId(), CALLER_REGION, "DescribeOrganization", "{}")
                .when().post("/").then().statusCode(400).body("__type", equalTo("AccessDeniedException"));
        OrganizationsRequests.request(credentials.accessKeyId(), CALLER_REGION, "LeaveOrganization", "{}")
                .when().post("/").then().statusCode(400).body("__type", equalTo("AccessDeniedException"));

        List<JsonNode> records = organizationsRecords(account, logs);
        JsonNode describe = only(records, "DescribeOrganization");
        assertThat(describe.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(describe.path("errorMessage").asText(), containsString("organizations:DescribeOrganization"));
        assertThat(describe.path("readOnly").asBoolean(), equalTo(true));
        assertThat(describe.path("awsRegion").asText(), equalTo(RECORDED_REGION));
        assertThat(describe.path("userIdentity").path("userName").asText(), equalTo(user));
        assertThat(describe.path("requestParameters").isNull(), equalTo(true));
        assertThat(describe.path("responseElements").isNull(), equalTo(true));
        JsonNode leave = only(records, "LeaveOrganization");
        assertThat(leave.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(leave.path("readOnly").asBoolean(true), equalTo(false));
    }

    private void createOrganization(String account) {
        call(account, "CreateOrganization", "{\"FeatureSet\":\"ALL\"}", 200);
        cleanup.register(() -> quietly(account, "DeleteOrganization", "{}"));
    }

    /** Creates a member account, registering its removal and its access role's, and returns its ID. */
    private String createAccount(String account) {
        String member = call(account, "CreateAccount", "{\"Email\":\"" + EMAIL + "\",\"AccountName\":\"ct-member\"}",
                200).getString("CreateAccountStatus.AccountId");
        cleanup.register(() -> quietly(account, "RemoveAccountFromOrganization",
                "{\"AccountId\":\"" + member + "\"}"));
        cleanup.register(() -> EnforcementFixtures.removeRole(baseUri.getPort(), auth(member, "iam"), ACCESS_ROLE));
        return member;
    }

    private static JsonPath call(String account, String action, String body, int status) {
        return OrganizationsRequests.request(account, CALLER_REGION, action, body).when().post("/").then()
                .statusCode(status).extract().jsonPath();
    }

    /** A cleanup call: it may find nothing left to delete. */
    private static void quietly(String account, String action, String body) {
        OrganizationsRequests.request(account, CALLER_REGION, action, body).when().post("/");
    }

    private static String json(String text) {
        return "\"" + text.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private static String account() {
        return "6615" + String.format("%08d", (int) (Math.random() * 100_000_000));
    }

    private void startTrail(String account, String trail, String bucket, boolean globalServiceEvents) {
        given().port(baseUri.getPort()).header("Authorization", auth(account, "s3"))
                .when().put("/" + bucket).then().statusCode(200);
        cleanup.register(() -> EnforcementFixtures.removeBucket(baseUri.getPort(), auth(account, "s3"), bucket));
        cloudTrail(account, "CreateTrail", "{\"Name\":\"" + trail + "\",\"S3BucketName\":\"" + bucket
                + "\",\"IncludeGlobalServiceEvents\":" + globalServiceEvents + "}");
        cleanup.register(() -> cloudTrail(account, "DeleteTrail", "{\"Name\":\"" + trail + "\"}"));
        cloudTrail(account, "StartLogging", "{\"Name\":\"" + trail + "\"}");
    }

    private static void cloudTrail(String account, String action, String body) {
        CloudTrailRequests.invokeCloudTrail(auth(account, "cloudtrail"), action, body).then().statusCode(200);
    }

    /** The Organizations records of {@code account}, read from the log files delivered to {@code bucket}. */
    private List<JsonNode> organizationsRecords(String account, String bucket) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(account, "s3")).stream()
                .filter(record -> "organizations.amazonaws.com".equals(record.path("eventSource").asText()))
                .toList();
    }

    private static List<JsonNode> named(List<JsonNode> records, String eventName) {
        return records.stream().filter(record -> eventName.equals(record.path("eventName").asText())).toList();
    }

    private static JsonNode only(List<JsonNode> records, String eventName) {
        List<JsonNode> found = named(records, eventName);
        assertThat(eventName + " in " + records, found, hasSize(1));
        return found.getFirst();
    }
}
