package io.floci.aws.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.aws.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.ValidatableResponse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

/**
 * {@code LookupEvents} answers the management events Floci records from event history, with no
 * trail at all, and filters and pages them as the API Reference describes.
 */
@QuarkusTest
class CloudTrailEventHistoryIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void managementEventsAreLookedUpWithoutATrail() throws Exception {
        String account = freshAccount();
        String name = "history-" + UUID.randomUUID().toString().substring(0, 8);
        secrets(account, "CreateSecret", "{\"Name\": \"" + name + "\", \"SecretString\": \"v1\"}").statusCode(200);
        secrets(account, "PutSecretValue", "{\"SecretId\": \"" + name + "\", \"SecretString\": \"v2\"}").statusCode(200);
        secrets(account, "UpdateSecret", "{\"SecretId\": \"" + name + "\", \"Description\": \"d\"}").statusCode(200);

        JsonNode all = lookup(account, """
                {"LookupAttributes": [{"AttributeKey": "EventSource",
                                       "AttributeValue": "secretsmanager.amazonaws.com"}]}""");
        assertThat(all.path("Events").toString(), all.path("Events").size(), equalTo(2));
        JsonNode latest = all.path("Events").get(0);
        assertThat(latest.path("EventName").asText(), equalTo("UpdateSecret"));
        assertThat(latest.path("EventSource").asText(), equalTo("secretsmanager.amazonaws.com"));
        assertThat(latest.path("ReadOnly").asText(), equalTo("false"));
        assertThat(latest.path("EventTime").isNumber(), equalTo(true));
        assertThat(latest.path("Resources").isArray(), equalTo(true));
        JsonNode record = MAPPER.readTree(latest.path("CloudTrailEvent").asText());
        assertThat(record.path("eventID").asText(), equalTo(latest.path("EventId").asText()));
        assertThat(record.path("recipientAccountId").asText(), equalTo(account));
        assertThat(all.path("Events").get(1).path("EventName").asText(), equalTo("PutSecretValue"));

        JsonNode byName = lookup(account, """
                {"LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "PutSecretValue"}]}""");
        assertThat(byName.path("Events").size(), equalTo(1));
        JsonNode byId = lookup(account, "{\"LookupAttributes\": [{\"AttributeKey\": \"EventId\", \"AttributeValue\": \""
                + latest.path("EventId").asText() + "\"}]}");
        assertThat(byId.path("Events").get(0).path("EventName").asText(), equalTo("UpdateSecret"));

        JsonNode firstPage = lookup(account, "{\"MaxResults\": 1}");
        assertThat(firstPage.path("Events").size(), equalTo(1));
        assertThat(firstPage.path("NextToken").asText(null), notNullValue());
        JsonNode secondPage = lookup(account, "{\"MaxResults\": 1, \"NextToken\": \""
                + firstPage.path("NextToken").asText() + "\"}");
        assertThat(secondPage.path("Events").get(0).path("EventName").asText(), equalTo("PutSecretValue"));
        assertThat(secondPage.path("NextToken").asText(null), nullValue());

        assertThat(lookup(account, "{\"EventCategory\": \"insight\"}").path("Events").size(), equalTo(0));
        assertThat(lookup(freshAccount(), "{}").path("Events").size(), equalTo(0));
    }

    @Test
    void invalidLookupsAreRefused() {
        String account = freshAccount();
        cloudTrail(account, "LookupEvents", """
                {"LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "a"},
                                      {"AttributeKey": "EventSource", "AttributeValue": "b"}]}""")
                .statusCode(400).body(containsString("InvalidLookupAttributesException"));
        cloudTrail(account, "LookupEvents", """
                {"LookupAttributes": [{"AttributeKey": "Nope", "AttributeValue": "a"}]}""")
                .statusCode(400).body(containsString("InvalidLookupAttributesException"));
        cloudTrail(account, "LookupEvents", "{\"StartTime\": 1700000100, \"EndTime\": 1700000000}")
                .statusCode(400).body(containsString("InvalidTimeRangeException"));
        cloudTrail(account, "LookupEvents", "{\"EventCategory\": \"management\"}")
                .statusCode(400).body(containsString("InvalidEventCategoryException"));
        cloudTrail(account, "LookupEvents", "{\"NextToken\": \"not-a-token\"}")
                .statusCode(400).body(containsString("InvalidNextTokenException"));
    }

    private static String freshAccount() {
        return "6611" + String.format("%08d", (int) (Math.random() * 100_000_000));
    }

    private static JsonNode lookup(String account, String body) throws Exception {
        String json = cloudTrail(account, "LookupEvents", body).statusCode(200).extract().asString();
        JsonNode answer = MAPPER.readTree(json);
        assertThat(json, answer.path("Events").isArray(), equalTo(true));
        return answer;
    }

    private static ValidatableResponse cloudTrail(String account, String action, String body) {
        return given()
                .header("Authorization", auth(account, REGION, "cloudtrail"))
                .header("X-Amz-Target", "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101." + action)
                .contentType("application/x-amz-json-1.1")
                .body(body)
                .when().post("/")
                .then();
    }

    private static ValidatableResponse secrets(String account, String action, String body) {
        return given()
                .header("Authorization", auth(account, REGION, "secretsmanager"))
                .header("X-Amz-Target", "secretsmanager." + action)
                .contentType("application/x-amz-json-1.1")
                .body(body)
                .when().post("/")
                .then();
    }
}
