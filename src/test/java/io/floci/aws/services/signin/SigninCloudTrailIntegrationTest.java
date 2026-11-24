package io.floci.aws.services.signin;

import com.fasterxml.jackson.databind.JsonNode;
import io.floci.aws.core.common.Base64Url;
import io.floci.aws.core.common.Digests;
import io.floci.aws.services.cloudtrail.CloudTrailLogWriter;
import io.floci.aws.testing.CloudTrailLogFiles;
import io.floci.aws.testing.CloudTrailRequests;
import io.floci.aws.testing.EnforcementFixtures;
import io.floci.aws.testing.PartitionCleanup;
import io.floci.aws.testing.RestAssuredJsonUtils;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;

/**
 * An {@code aws login} leaves its two calls in a trail, AuthorizeOAuth2Access and CreateOAuth2Token, with only the
 * members AWS's records of them keep: never the code, the verifier, the refresh token or the credentials.
 */
@QuarkusTest
class SigninCloudTrailIntegrationTest {

    private static final String CLIENT_ID = "arn:aws:signin:::devtools/same-device";
    private static final String REDIRECT_URI = "http://127.0.0.1:53037/oauth/callback";
    private static final String BROWSER = "Mozilla/5.0 (X11; Linux x86_64) Floci-Test-Browser";
    private static final String CLI = "aws-cli/2.32.0 md/command#login";
    private static final String DEFAULT_KEY = "test";

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
    void loginRecordsAuthorizationAndTokenCallsWithoutSecrets() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-signin-logs-" + suffix;
        startTrail("ct-signin-" + suffix, logs);
        String verifier = "verifier-" + UUID.randomUUID() + "-" + UUID.randomUUID();
        String state = "state-" + UUID.randomUUID();

        String code = authorize(verifier, state);
        Response token = given().header("User-Agent", CLI).contentType("application/json")
                .body(Map.of("clientId", CLIENT_ID, "grantType", "authorization_code", "code", code,
                        "redirectUri", REDIRECT_URI, "codeVerifier", verifier))
                .when().post("/v1/token").then().statusCode(200).extract().response();
        String refreshToken = token.path("refreshToken");
        Response refreshed = given().header("User-Agent", CLI).contentType("application/json")
                .body(Map.of("clientId", CLIENT_ID, "grantType", "refresh_token", "refreshToken", refreshToken))
                .when().post("/v1/token").then().statusCode(200).extract().response();
        given().header("User-Agent", CLI).contentType("application/json")
                .body(Map.of("clientId", CLIENT_ID, "grantType", "authorization_code", "code", code,
                        "redirectUri", REDIRECT_URI, "codeVerifier", verifier))
                .when().post("/v1/token").then().statusCode(400);

        List<JsonNode> records = signinRecords(logs);
        List<String> secrets = new ArrayList<>(List.of(code, verifier, challenge(verifier), state, refreshToken,
                refreshed.path("refreshToken"), token.path("accessToken.accessKeyId"),
                token.path("accessToken.secretAccessKey"), token.path("accessToken.sessionToken"),
                refreshed.path("accessToken.secretAccessKey"), refreshed.path("accessToken.sessionToken")));
        for (String secret : secrets) {
            assertThat(records.toString(), not(containsString(secret)));
        }

        List<JsonNode> authorizations = named(records, "AuthorizeOAuth2Access");
        assertThat(authorizations, hasSize(1));
        JsonNode authorization = authorizations.getFirst();
        assertSignin(authorization, BROWSER);
        JsonNode parameters = authorization.path("requestParameters");
        assertThat(fieldNames(parameters), containsInAnyOrder("scope", "redirect_uri", "code_challenge_method",
                "client_id"));
        assertThat(parameters.path("scope").asText(), equalTo("openid"));
        assertThat(parameters.path("redirect_uri").asText(), equalTo(REDIRECT_URI));
        assertThat(parameters.path("code_challenge_method").asText(), equalTo("SHA-256"));
        assertThat(parameters.path("client_id").asText(), equalTo(CLIENT_ID));

        List<JsonNode> tokens = named(records, "CreateOAuth2Token");
        assertThat("a refused exchange is not recorded", tokens, hasSize(2));
        for (JsonNode created : tokens) {
            assertSignin(created, CLI);
            assertThat(fieldNames(created.path("requestParameters")), containsInAnyOrder("client_id"));
            assertThat(created.path("requestParameters").path("client_id").asText(), equalTo(CLIENT_ID));
        }
    }

    @Test
    void cancelledConsentIsNotRecordedAsAnAuthorization() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-signin-cancel-" + suffix;
        startTrail("ct-signin-cancel-" + suffix, logs);

        String consent = consentLocation(verifierOf(suffix), "state-" + suffix);
        given().redirects().follow(false).contentType("application/x-www-form-urlencoded")
                .formParam("request_id", queryParams(URI.create(consent).getRawQuery()).get("request_id"))
                .formParam("action", "cancel")
                .when().post("/_floci/signin/consent").then().statusCode(302);

        assertThat(named(signinRecords(logs), "AuthorizeOAuth2Access"), hasSize(0));
    }

    private static void assertSignin(JsonNode record, String userAgent) {
        String account = record.path("recipientAccountId").asText();
        assertThat(record.path("eventSource").asText(), equalTo("signin.amazonaws.com"));
        assertThat(record.path("eventType").asText(), equalTo("AwsApiCall"));
        assertThat(record.path("managementEvent").asBoolean(), equalTo(true));
        assertThat(record.path("readOnly").asBoolean(), equalTo(true));
        assertThat(record.path("responseElements").isNull(), equalTo(true));
        assertThat(record.path("additionalEventData").path("success").asText(), equalTo("true"));
        assertThat(record.path("additionalEventData").has("x-amzn-vpce-id"), equalTo(true));
        assertThat(record.path("additionalEventData").path("x-amzn-vpce-id").asText(), equalTo(""));
        assertThat(record.path("userAgent").asText(), equalTo(userAgent));
        JsonNode identity = record.path("userIdentity");
        assertThat(identity.path("type").asText(), equalTo("Root"));
        assertThat(identity.path("accountId").asText(), equalTo(account));
        assertThat(identity.path("arn").asText(), equalTo("arn:aws:iam::" + account + ":root"));
        assertThat(identity.has("accessKeyId"), equalTo(false));
    }

    private String authorize(String verifier, String state) throws Exception {
        String consent = consentLocation(verifier, state);
        String redirect = given().redirects().follow(false).header("User-Agent", BROWSER)
                .contentType("application/x-www-form-urlencoded")
                .formParam("request_id", queryParams(URI.create(consent).getRawQuery()).get("request_id"))
                .formParam("action", "continue")
                .when().post("/_floci/signin/consent").then().statusCode(302).extract().header("Location");
        return queryParams(URI.create(redirect).getRawQuery()).get("code");
    }

    private static String consentLocation(String verifier, String state) throws Exception {
        return given().redirects().follow(false).header("User-Agent", BROWSER)
                .queryParam("client_id", CLIENT_ID)
                .queryParam("code_challenge", challenge(verifier))
                .queryParam("code_challenge_method", "SHA-256")
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("response_type", "code")
                .queryParam("scope", "openid")
                .queryParam("state", state)
                .when().get("/v1/authorize").then().statusCode(302).extract().header("Location");
    }

    private void startTrail(String trail, String bucket) {
        given().header("Authorization", auth(DEFAULT_KEY, "s3")).when().put("/" + bucket).then().statusCode(200);
        cleanup.register(() -> EnforcementFixtures.removeBucket(baseUri.getPort(), auth(DEFAULT_KEY, "s3"), bucket));
        cloudTrail("CreateTrail", "{\"Name\":\"" + trail + "\",\"S3BucketName\":\"" + bucket + "\"}");
        cleanup.register(() -> cloudTrail("DeleteTrail", "{\"Name\":\"" + trail + "\"}"));
        cloudTrail("StartLogging", "{\"Name\":\"" + trail + "\"}");
    }

    private static void cloudTrail(String action, String body) {
        CloudTrailRequests.invokeCloudTrail(auth(DEFAULT_KEY, "cloudtrail"), action, body).then().statusCode(200);
    }

    private List<JsonNode> signinRecords(String bucket) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(DEFAULT_KEY, "s3")).stream()
                .filter(record -> "signin.amazonaws.com".equals(record.path("eventSource").asText()))
                .toList();
    }

    private static List<JsonNode> named(List<JsonNode> records, String eventName) {
        return records.stream().filter(record -> eventName.equals(record.path("eventName").asText())).toList();
    }

    private static List<String> fieldNames(JsonNode node) {
        List<String> names = new ArrayList<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }

    private static String verifierOf(String suffix) {
        return "verifier-" + suffix + "-abcdefghijklmnopqrstuvwxyz0123456789";
    }

    private static String challenge(String verifier) throws Exception {
        return Base64Url.encode(Digests.sha256(verifier.getBytes(StandardCharsets.US_ASCII)));
    }

    private static Map<String, String> queryParams(String query) {
        return Arrays.stream(query.split("&"))
                .map(pair -> pair.split("=", 2))
                .collect(Collectors.toMap(
                        parts -> URLDecoder.decode(parts[0], StandardCharsets.UTF_8),
                        parts -> URLDecoder.decode(parts[1], StandardCharsets.UTF_8)));
    }
}
