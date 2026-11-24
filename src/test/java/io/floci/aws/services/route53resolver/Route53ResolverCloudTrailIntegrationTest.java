package io.floci.aws.services.route53resolver;

import com.fasterxml.jackson.databind.JsonNode;
import io.floci.aws.services.cloudtrail.CloudTrailLogWriter;
import io.floci.aws.testing.CloudTrailLogFiles;
import io.floci.aws.testing.CloudTrailRequests;
import io.floci.aws.testing.EnforcementFixtures;
import io.floci.aws.testing.IamEnforcementProfile;
import io.floci.aws.testing.PartitionCleanup;
import io.floci.aws.testing.RestAssuredJsonUtils;
import io.floci.aws.testing.Route53ResolverRequests;
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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;

/**
 * Route 53 Resolver calls reach a trail's log files as management events of the Region they were made in, a
 * trail that leaves global service events out included, with their members, their answers, their errors and
 * their refusals.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class Route53ResolverCloudTrailIntegrationTest {

    private static final String REGION = "eu-west-1";

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
    void callsAreRecordedInTheirRegionWithTheirMembersAndAnswers() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-r53r-logs-" + suffix;
        startTrail(account, "ct-r53r-" + suffix, logs);

        String name = "ct-blocklist-" + suffix;
        JsonPath created = call(account, "CreateFirewallDomainList", "{\"CreatorRequestId\":\"" + suffix
                + "\",\"Name\":\"" + name + "\",\"Tags\":[{\"Key\":\"team\",\"Value\":\"dns\"}]}", 200);
        String list = created.getString("FirewallDomainList.Id");
        String arn = created.getString("FirewallDomainList.Arn");
        cleanup.register(() -> Route53ResolverRequests.call("DeleteFirewallDomainList",
                "{\"FirewallDomainListId\":\"" + list + "\"}", auth(account, REGION, "route53resolver")));
        call(account, "GetFirewallDomainList", "{\"FirewallDomainListId\":\"" + list + "\"}", 200);
        call(account, "UntagResource", "{\"ResourceArn\":\"" + arn + "\",\"TagKeys\":[\"team\"]}", 200);
        JsonPath missing = call(account, "GetFirewallDomainList",
                "{\"FirewallDomainListId\":\"rslvr-fdl-0000000000000000\"}", 404);
        call(account, "DeleteFirewallDomainList", "{\"FirewallDomainListId\":\"" + list + "\"}", 200);

        List<JsonNode> records = resolverRecords(account, logs);
        for (JsonNode record : records) {
            assertThat(record.toString(), record.path("awsRegion").asText(), equalTo(REGION));
            assertThat(record.toString(), record.has("apiVersion"), equalTo(false));
            assertThat(record.path("recipientAccountId").asText(), equalTo(account));
        }

        JsonNode create = only(records, "CreateFirewallDomainList");
        assertThat(create.path("readOnly").asBoolean(true), equalTo(false));
        assertThat(create.path("requestParameters").path("creatorRequestId").asText(), equalTo(suffix));
        assertThat(create.path("requestParameters").path("name").asText(), equalTo(name));
        assertThat(create.path("requestParameters").path("tags").path(0).path("key").asText(), equalTo("team"));
        assertThat(create.path("responseElements").path("firewallDomainList").path("id").asText(), equalTo(list));
        assertThat(create.path("responseElements").path("firewallDomainList").path("arn").asText(), equalTo(arn));

        List<JsonNode> gets = named(records, "GetFirewallDomainList");
        assertThat(gets, hasSize(2));
        JsonNode read = gets.stream().filter(record -> !record.has("errorCode")).findFirst().orElseThrow();
        assertThat(read.path("readOnly").asBoolean(), equalTo(true));
        assertThat(read.path("requestParameters").path("firewallDomainListId").asText(), equalTo(list));
        assertThat(read.path("responseElements").isNull(), equalTo(true));
        JsonNode failed = gets.stream().filter(record -> record.has("errorCode")).findFirst().orElseThrow();
        assertThat(failed.path("errorCode").asText(), equalTo(missing.getString("__type")));
        assertThat(failed.path("errorMessage").asText(), equalTo(missing.getString("message")));
        assertThat(failed.path("requestParameters").path("firewallDomainListId").asText(),
                equalTo("rslvr-fdl-0000000000000000"));
        assertThat(failed.path("responseElements").isNull(), equalTo(true));

        JsonNode untag = only(records, "UntagResource");
        assertThat(untag.path("readOnly").asBoolean(true), equalTo(false));
        assertThat(untag.path("requestParameters").path("tagKeys").path(0).asText(), equalTo("team"));

        JsonNode delete = only(records, "DeleteFirewallDomainList");
        assertThat(delete.path("readOnly").asBoolean(true), equalTo(false));
        assertThat(delete.path("responseElements").path("firewallDomainList").path("id").asText(), equalTo(list));
    }

    @Test
    void aRefusedCallIsRecordedWithoutItsMembers() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-r53r-refused-" + suffix;
        startTrail(account, "ct-r53r-refused-" + suffix, logs);
        String user = "ct-user-" + suffix;
        String key = EnforcementFixtures.createUser(cleanup, baseUri.getPort(), auth(account, "iam"), user)
                .accessKeyId();

        Route53ResolverRequests.call("DeleteFirewallDomainList",
                "{\"FirewallDomainListId\":\"rslvr-fdl-0000000000000000\"}", auth(key, REGION, "route53resolver"))
                .statusCode(400).body("__type", equalTo("AccessDeniedException"));

        JsonNode refused = only(resolverRecords(account, logs), "DeleteFirewallDomainList");
        assertThat(refused.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(refused.path("errorMessage").asText(), containsString("route53resolver:DeleteFirewallDomainList"));
        assertThat(refused.path("awsRegion").asText(), equalTo(REGION));
        assertThat(refused.path("readOnly").asBoolean(true), equalTo(false));
        assertThat(refused.path("userIdentity").path("userName").asText(), equalTo(user));
        assertThat(refused.path("requestParameters").isNull(), equalTo(true));
        assertThat(refused.path("responseElements").isNull(), equalTo(true));
    }

    private static JsonPath call(String account, String action, String body, int status) {
        return Route53ResolverRequests.call(action, body, auth(account, REGION, "route53resolver"))
                .statusCode(status).extract().jsonPath();
    }

    private static String account() {
        return "6635" + String.format("%08d", (int) (Math.random() * 100_000_000));
    }

    /** A trail in the calls' Region that leaves global service events out, which Resolver's are not. */
    private void startTrail(String account, String trail, String bucket) {
        given().port(baseUri.getPort()).header("Authorization", auth(account, "s3"))
                .when().put("/" + bucket).then().statusCode(200);
        cleanup.register(() -> EnforcementFixtures.removeBucket(baseUri.getPort(), auth(account, "s3"), bucket));
        cloudTrail(account, "CreateTrail", "{\"Name\":\"" + trail + "\",\"S3BucketName\":\"" + bucket
                + "\",\"IncludeGlobalServiceEvents\":false,\"IsMultiRegionTrail\":true}");
        cleanup.register(() -> cloudTrail(account, "DeleteTrail", "{\"Name\":\"" + trail + "\"}"));
        cloudTrail(account, "StartLogging", "{\"Name\":\"" + trail + "\"}");
    }

    private static void cloudTrail(String account, String action, String body) {
        CloudTrailRequests.invokeCloudTrail(auth(account, "cloudtrail"), action, body).then().statusCode(200);
    }

    /** The Resolver records of {@code account}, read from the log files delivered to {@code bucket}. */
    private List<JsonNode> resolverRecords(String account, String bucket) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(account, "s3")).stream()
                .filter(record -> "route53resolver.amazonaws.com".equals(record.path("eventSource").asText()))
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
