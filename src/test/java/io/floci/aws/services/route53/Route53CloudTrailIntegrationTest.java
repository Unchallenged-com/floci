package io.floci.aws.services.route53;

import com.fasterxml.jackson.databind.JsonNode;
import io.floci.aws.services.cloudtrail.CloudTrailLogWriter;
import io.floci.aws.testing.CloudTrailLogFiles;
import io.floci.aws.testing.CloudTrailRequests;
import io.floci.aws.testing.EnforcementFixtures;
import io.floci.aws.testing.IamEnforcementProfile;
import io.floci.aws.testing.PartitionCleanup;
import io.floci.aws.testing.RestAssuredJsonUtils;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
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

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.matchesPattern;

/**
 * Route 53 calls reach a trail's log files as management events recorded in us-east-1, whatever Region the
 * caller signed for, and only a trail that includes global service events records them: with their members,
 * their answers, their errors and their refusals.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class Route53CloudTrailIntegrationTest {

    private static final String XML = "application/xml";
    private static final String NS = "https://route53.amazonaws.com/doc/2013-04-01/";
    private static final String CALLER_REGION = "eu-west-1";
    private static final String RECORDED_REGION = "us-east-1";
    private static final String SUBMITTED_AT = "[A-Z][a-z]{2} \\d{1,2}, \\d{4} \\d{1,2}:\\d{2}:\\d{2} [AP]M";

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
        String logs = "ct-r53-logs-" + suffix;
        String regional = "ct-r53-regional-" + suffix;
        startTrail(account, "ct-r53-" + suffix, logs, true);
        startTrail(account, "ct-r53-regional-" + suffix, regional, false);

        String zoneName = "ct-" + suffix + ".example.com";
        String caller = "ct-" + suffix;
        String location = route53(account).contentType(XML).body("""
                <CreateHostedZoneRequest xmlns="%s"><Name>%s</Name><CallerReference>%s</CallerReference>
                <HostedZoneConfig><Comment>ct zone</Comment></HostedZoneConfig></CreateHostedZoneRequest>
                """.formatted(NS, zoneName, caller))
                .post("/2013-04-01/hostedzone").then().statusCode(201).extract().header("Location");
        String zone = location.substring(location.lastIndexOf('/') + 1);
        cleanup.register(() -> route53(account).delete("/2013-04-01/hostedzone/" + zone));

        route53(account).contentType(XML).body("""
                <ChangeResourceRecordSetsRequest xmlns="%s"><ChangeBatch><Comment>mail</Comment><Changes>
                <Change><Action>CREATE</Action><ResourceRecordSet><Name>mx.%s.</Name><Type>A</Type><TTL>300</TTL>
                <ResourceRecords><ResourceRecord><Value>192.0.2.10</Value></ResourceRecord>
                <ResourceRecord><Value>192.0.2.11</Value></ResourceRecord></ResourceRecords>
                </ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>
                """.formatted(NS, zoneName))
                .post("/2013-04-01/hostedzone/" + zone + "/rrset").then().statusCode(200);
        route53(account).get("/2013-04-01/hostedzone").then().statusCode(200);
        route53(account).queryParam("maxitems", "10").get("/2013-04-01/hostedzone/" + zone + "/rrset")
                .then().statusCode(200);
        String missing = route53(account).get("/2013-04-01/hostedzone/ZNONE000000000")
                .then().statusCode(404).extract().xmlPath().getString("ErrorResponse.Error.Message");
        route53(account).contentType(XML).body("""
                <ChangeResourceRecordSetsRequest xmlns="%s"><ChangeBatch><Changes>
                <Change><Action>DELETE</Action><ResourceRecordSet><Name>mx.%s.</Name><Type>A</Type><TTL>300</TTL>
                <ResourceRecords><ResourceRecord><Value>192.0.2.10</Value></ResourceRecord>
                <ResourceRecord><Value>192.0.2.11</Value></ResourceRecord></ResourceRecords>
                </ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>
                """.formatted(NS, zoneName))
                .post("/2013-04-01/hostedzone/" + zone + "/rrset").then().statusCode(200);
        route53(account).delete("/2013-04-01/hostedzone/" + zone).then().statusCode(200);

        List<JsonNode> records = route53Records(account, logs);
        for (JsonNode record : records) {
            assertThat(record.toString(), record.path("awsRegion").asText(), equalTo(RECORDED_REGION));
            assertThat(record.toString(), record.path("apiVersion").asText(), equalTo("2013-04-01"));
            assertThat(record.path("recipientAccountId").asText(), equalTo(account));
        }
        assertThat(route53Records(account, regional), empty());

        JsonNode created = only(records, "CreateHostedZone");
        assertThat(created.path("readOnly").asBoolean(true), equalTo(false));
        assertThat(created.path("requestParameters").path("name").asText(), equalTo(zoneName));
        assertThat(created.path("requestParameters").path("callerReference").asText(), equalTo(caller));
        assertThat(created.path("requestParameters").path("hostedZoneConfig").path("comment").asText(),
                equalTo("ct zone"));
        assertThat(created.path("responseElements").path("hostedZone").path("id").asText(),
                equalTo("/hostedzone/" + zone));
        assertThat(created.path("responseElements").path("changeInfo").path("submittedAt").asText(),
                matchesPattern(SUBMITTED_AT));
        assertThat(created.path("responseElements").path("location").asText(), endsWith("/hostedzone/" + zone));

        List<JsonNode> changes = named(records, "ChangeResourceRecordSets");
        assertThat(changes, hasSize(2));
        JsonNode change = changes.stream()
                .filter(record -> "mail".equals(record.path("requestParameters").path("changeBatch")
                        .path("comment").asText())).findFirst().orElseThrow();
        assertThat(change.path("requestParameters").path("hostedZoneId").asText(), equalTo(zone));
        JsonNode set = change.path("requestParameters").path("changeBatch").path("changes").path(0);
        assertThat(set.path("action").asText(), equalTo("CREATE"));
        assertThat(set.path("resourceRecordSet").path("name").asText(), equalTo("mx." + zoneName + "."));
        assertThat(set.path("resourceRecordSet").path("tTL").isNumber(), equalTo(true));
        assertThat(set.path("resourceRecordSet").path("tTL").asInt(), equalTo(300));
        assertThat(set.path("resourceRecordSet").path("resourceRecords").path(1).path("value").asText(),
                equalTo("192.0.2.11"));
        assertThat(change.path("responseElements").path("changeInfo").path("status").asText(), equalTo("INSYNC"));
        assertThat(change.path("additionalEventData").path("Note").asText(),
                equalTo("Do not use to reconstruct hosted zone"));

        JsonNode listed = only(records, "ListHostedZones");
        assertThat(listed.path("readOnly").asBoolean(), equalTo(true));
        assertThat(listed.path("requestParameters").isNull(), equalTo(true));
        assertThat(listed.path("responseElements").isNull(), equalTo(true));
        JsonNode sets = only(records, "ListResourceRecordSets");
        assertThat(sets.path("requestParameters").path("hostedZoneId").asText(), equalTo(zone));
        assertThat(sets.path("requestParameters").path("maxItems").asText(), equalTo("10"));

        JsonNode failed = named(records, "GetHostedZone").stream()
                .filter(record -> record.has("errorCode")).findFirst().orElseThrow();
        assertThat(failed.path("errorCode").asText(), equalTo("NoSuchHostedZone"));
        assertThat(failed.path("errorMessage").asText(), equalTo(missing));
        assertThat(failed.path("requestParameters").path("id").asText(), equalTo("ZNONE000000000"));
        assertThat(failed.path("responseElements").isNull(), equalTo(true));

        JsonNode deleted = only(records, "DeleteHostedZone");
        assertThat(deleted.path("readOnly").asBoolean(true), equalTo(false));
        assertThat(deleted.path("requestParameters").path("id").asText(), equalTo(zone));
        assertThat(deleted.path("responseElements").path("changeInfo").path("id").asText(),
                matchesPattern("/change/.+"));
    }

    @Test
    void aRefusedCallIsRecordedWithoutItsMembers() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-r53-refused-" + suffix;
        startTrail(account, "ct-r53-refused-" + suffix, logs, true);
        String user = "ct-user-" + suffix;
        String key = EnforcementFixtures.createUser(cleanup, baseUri.getPort(), auth(account, "iam"), user)
                .accessKeyId();

        route53(key).contentType(XML).body("""
                <CreateHostedZoneRequest xmlns="%s"><Name>refused-%s.example.com</Name>
                <CallerReference>%s</CallerReference></CreateHostedZoneRequest>
                """.formatted(NS, suffix, suffix))
                .post("/2013-04-01/hostedzone").then().statusCode(403);
        route53(key).get("/2013-04-01/hostedzone").then().statusCode(403);

        List<JsonNode> records = route53Records(account, logs);
        JsonNode create = only(records, "CreateHostedZone");
        assertThat(create.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(create.path("errorMessage").asText(), containsString("route53:CreateHostedZone"));
        assertThat(create.path("awsRegion").asText(), equalTo(RECORDED_REGION));
        assertThat(create.path("readOnly").asBoolean(true), equalTo(false));
        assertThat(create.path("userIdentity").path("userName").asText(), equalTo(user));
        assertThat(create.path("requestParameters").isNull(), equalTo(true));
        assertThat(create.path("responseElements").isNull(), equalTo(true));
        assertThat(create.has("apiVersion"), equalTo(false));
        JsonNode list = only(records, "ListHostedZones");
        assertThat(list.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(list.path("readOnly").asBoolean(), equalTo(true));
    }

    /** A Route 53 request signed by {@code accessKeyId} for a Region other than us-east-1. */
    private static RequestSpecification route53(String accessKeyId) {
        return given().port(baseUri.getPort()).header("Authorization", auth(accessKeyId, CALLER_REGION, "route53"));
    }

    private static String account() {
        return "6625" + String.format("%08d", (int) (Math.random() * 100_000_000));
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

    private static ValidatableResponse cloudTrail(String account, String action, String body) {
        return CloudTrailRequests.invokeCloudTrail(auth(account, "cloudtrail"), action, body).then().statusCode(200);
    }

    /** The Route 53 records of {@code account}, read from the log files delivered to {@code bucket}. */
    private List<JsonNode> route53Records(String account, String bucket) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(account, "s3")).stream()
                .filter(record -> "route53.amazonaws.com".equals(record.path("eventSource").asText()))
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
