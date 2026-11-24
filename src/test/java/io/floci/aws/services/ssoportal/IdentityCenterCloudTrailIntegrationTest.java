package io.floci.aws.services.ssoportal;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.Base64Url;
import io.floci.aws.core.common.Digests;
import io.floci.aws.services.cloudtrail.CloudTrailLogWriter;
import io.floci.aws.services.identitystore.IdentityStoreService;
import io.floci.aws.services.ssoadmin.SsoAdminService;
import io.floci.aws.services.ssooidc.SsoOidcService;
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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;

/**
 * IAM Identity Center's credential calls reach a trail as AWS records them: CreateToken and the access portal's
 * calls as the user's, CreateTokenWithIAM as its signer's, with tokens, secrets and role credentials hidden or left out.
 */
@QuarkusTest
class IdentityCenterCloudTrailIntegrationTest {

    private static final String DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
    private static final String HIDDEN = "HIDDEN_DUE_TO_SECURITY_REASONS";
    private static final String CLI = "aws-cli/2.32.3 md/command#sso.login";
    private static final String DEFAULT_KEY = "test";
    private static final String MEMBER_ACCOUNT = "111111111111";

    @TestHTTPResource("/")
    static URI baseUri;

    @Inject
    CloudTrailLogWriter writer;

    @Inject
    ObjectMapper mapper;

    @Inject
    IdentityStoreService identityStore;

    @Inject
    SsoAdminService ssoAdmin;

    @Inject
    SsoOidcService oidc;

    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void deviceLoginAndPortalCallsAreTheUsers() throws IOException {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-sso-logs-" + suffix;
        startTrail("ct-sso-" + suffix, logs);
        String userId = createUser(suffix);
        String permissionSet = "CtPortal" + suffix;
        assign(userId, permissionSet);

        Response registration = given().contentType("application/json")
                .body("{\"clientName\":\"ct-" + suffix + "\",\"clientType\":\"public\",\"grantTypes\":[\""
                        + DEVICE_CODE_GRANT + "\",\"refresh_token\"]}")
                .when().post("/client/register").then().statusCode(200).extract().response();
        String clientId = registration.path("clientId");
        String clientSecret = registration.path("clientSecret");
        Response device = given().contentType("application/json")
                .body("{\"clientId\":\"" + clientId + "\",\"clientSecret\":\"" + clientSecret
                        + "\",\"startUrl\":\"https://example.awsapps.com/start\"}")
                .when().post("/device_authorization").then().statusCode(200).extract().response();
        String deviceCode = device.path("deviceCode");
        String tokenBody = "{\"clientId\":\"" + clientId + "\",\"clientSecret\":\"" + clientSecret
                + "\",\"grantType\":\"" + DEVICE_CODE_GRANT + "\",\"deviceCode\":\"" + deviceCode + "\"}";
        oidc.authorizeDevice(device.path("userCode"), userId);
        given().header("User-Agent", CLI).contentType("application/json")
                .body(tokenBody.replace(clientSecret, "wrong-" + suffix))
                .when().post("/token").then().statusCode(greaterThanOrEqualTo(400));
        Response token = given().header("User-Agent", CLI).contentType("application/json").body(tokenBody)
                .when().post("/token").then().statusCode(200).extract().response();
        String accessToken = token.path("accessToken");
        String refreshToken = token.path("refreshToken");

        given().header("x-amz-sso_bearer_token", accessToken).header("User-Agent", CLI)
                .when().get("/assignment/accounts").then().statusCode(200);
        given().header("x-amz-sso_bearer_token", accessToken).header("User-Agent", CLI)
                .queryParam("account_id", MEMBER_ACCOUNT)
                .when().get("/assignment/roles").then().statusCode(200);
        Response credentials = given().header("x-amz-sso_bearer_token", accessToken).header("User-Agent", CLI)
                .queryParam("account_id", MEMBER_ACCOUNT).queryParam("role_name", permissionSet)
                .when().get("/federation/credentials").then().statusCode(200).extract().response();

        List<JsonNode> records = records(logs, "sso.amazonaws.com");
        for (String secret : List.of(clientSecret, accessToken, refreshToken,
                credentials.<String>path("roleCredentials.secretAccessKey"),
                credentials.<String>path("roleCredentials.sessionToken"))) {
            assertThat(records.toString(), not(containsString(secret)));
        }

        List<JsonNode> tokens = named(records, "CreateToken");
        assertThat("a refused request is not recorded", tokens, hasSize(1));
        JsonNode created = tokens.getFirst();
        String account = created.path("recipientAccountId").asText();
        String storeArn = "arn:aws:identitystore::" + account + ":identitystore/" + ssoAdmin.getIdentityStoreId();
        JsonNode identity = created.path("userIdentity");
        assertUser(identity, account, userId, storeArn);
        assertThat(created.path("eventType").asText(), equalTo("AwsApiCall"));
        assertThat(created.path("readOnly").asBoolean(true), equalTo(false));
        assertThat(created.path("userAgent").asText(), equalTo(CLI));
        JsonNode request = created.path("requestParameters");
        assertThat(fieldNames(request), contains("clientId", "clientSecret", "grantType", "deviceCode"));
        assertThat(request.path("clientId").asText(), equalTo(clientId));
        assertThat(request.path("clientSecret").asText(), equalTo(HIDDEN));
        assertThat(request.path("grantType").asText(), equalTo(DEVICE_CODE_GRANT));
        assertThat(request.path("deviceCode").asText(), equalTo(deviceCode));
        JsonNode answer = created.path("responseElements");
        assertThat(answer.path("accessToken").asText(), equalTo(HIDDEN));
        assertThat(answer.path("refreshToken").asText(), equalTo(HIDDEN));
        assertThat(answer.path("tokenType").asText(), equalTo("Bearer"));
        assertThat(answer.path("expiresIn").isInt(), equalTo(true));
        JsonNode store = created.path("resources").path(0);
        assertThat(store.path("type").asText(), equalTo("IdentityStoreId"));
        assertThat(store.path("ARN").asText(), equalTo(ssoAdmin.getIdentityStoreId()));
        assertThat(store.path("accountId").asText(), equalTo(account));
        String credentialId = identity.path("credentialId").asText();

        JsonNode accounts = only(records, "ListAccounts");
        assertPortal(accounts, account, userId, storeArn, credentialId);
        assertThat(accounts.has("serviceEventDetails"), equalTo(false));
        JsonNode roles = only(records, "ListAccountRoles");
        assertPortal(roles, account, userId, storeArn, credentialId);
        assertThat(fieldNames(roles.path("serviceEventDetails")), contains("account_id"));
        assertThat(roles.path("serviceEventDetails").path("account_id").asText(), equalTo(MEMBER_ACCOUNT));
        JsonNode role = only(records, "GetRoleCredentials");
        assertPortal(role, account, userId, storeArn, credentialId);
        assertThat(fieldNames(role.path("serviceEventDetails")), contains("role_name", "account_id"));
        assertThat(role.path("serviceEventDetails").path("role_name").asText(), equalTo(permissionSet));
        assertThat(role.path("serviceEventDetails").path("account_id").asText(), equalTo(MEMBER_ACCOUNT));
    }

    @Test
    void createTokenWithIamIsItsSignersWithTheTokenUser() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-sso-iam-logs-" + suffix;
        startTrail("ct-sso-iam-" + suffix, logs);
        String userId = createUser(suffix);
        String redirectUri = "http://127.0.0.1:8400/iam-callback";
        String applicationArn = createIamApplication(suffix, redirectUri);
        String verifier = "verifier-" + UUID.randomUUID() + "-" + UUID.randomUUID();
        String challenge = Base64Url.encode(Digests.sha256(verifier.getBytes(StandardCharsets.US_ASCII)));
        String code = oidc.createAuthorizationCodeForPrincipal(applicationArn, redirectUri, challenge,
                List.of(redirectUri), userId).code();
        String body = "{\"clientId\":\"" + applicationArn + "\",\"grantType\":\"authorization_code\","
                + "\"code\":\"" + code + "\",\"codeVerifier\":\"" + verifier + "\","
                + "\"redirectUri\":\"" + redirectUri + "\",\"scope\":[\"openid\"]}";
        String authorization = auth(DEFAULT_KEY, "us-east-1", "sso-oauth");

        Response token = given().header("Authorization", authorization).contentType("application/json").body(body)
                .when().post("/token?aws_iam=t").then().statusCode(200).extract().response();
        given().header("Authorization", authorization).contentType("application/json").body(body)
                .when().post("/token?aws_iam=t").then().statusCode(400);
        given().contentType("application/json").body(body.replace(code, "unsigned-" + suffix))
                .when().post("/token?aws_iam=t").then().statusCode(400);

        List<JsonNode> records = named(records(logs, "sso-oauth.amazonaws.com"), "CreateTokenWithIAM");
        for (String secret : new ArrayList<>(List.of(code, verifier, token.path("accessToken"),
                token.path("refreshToken"), token.path("idToken")))) {
            assertThat(records.toString(), not(containsString(secret)));
        }
        assertThat("an unsigned request is not recorded", records, hasSize(2));
        JsonNode created = records.stream().filter(record -> !record.has("errorCode")).findFirst().orElseThrow();
        JsonNode failed = records.stream().filter(record -> record.has("errorCode")).findFirst().orElseThrow();

        String account = created.path("recipientAccountId").asText();
        assertThat(created.path("userIdentity").path("accessKeyId").asText(), equalTo(DEFAULT_KEY));
        assertThat(created.path("readOnly").asBoolean(true), equalTo(false));
        assertThat(created.path("eventType").asText(), equalTo("AwsApiCall"));
        JsonNode request = created.path("requestParameters");
        assertThat(fieldNames(request), containsInAnyOrder("clientId", "grantType", "code", "codeVerifier",
                "redirectUri", "scope"));
        assertThat(request.path("clientId").asText(), equalTo(applicationArn));
        assertThat(request.path("grantType").asText(), equalTo("authorization_code"));
        assertThat(request.path("code").asText(), equalTo(HIDDEN));
        assertThat(request.path("codeVerifier").asText(), equalTo(HIDDEN));
        assertThat(request.path("redirectUri").asText(), equalTo(redirectUri));
        assertThat(request.path("scope").path(0).asText(), equalTo("openid"));
        JsonNode answer = created.path("responseElements");
        assertThat(fieldNames(answer), containsInAnyOrder("accessToken", "tokenType", "expiresIn", "refreshToken",
                "issuedTokenType"));
        assertThat(answer.path("accessToken").asText(), equalTo(HIDDEN));
        assertThat(answer.path("refreshToken").asText(), equalTo(HIDDEN));
        assertThat(answer.path("issuedTokenType").asText(), equalTo("urn:ietf:params:oauth:token-type:access_token"));
        JsonNode user = created.path("additionalEventData");
        assertThat(user.path("identitystore:UserId").asText(), equalTo(userId));
        assertThat(user.path("identitystore:IdentityStoreArn").asText(), equalTo(
                "arn:aws:identitystore::" + account + ":identitystore/" + ssoAdmin.getIdentityStoreId()));
        assertThat(user.path("identitycenter:CredentialId").asText(), not(equalTo("")));
        JsonNode application = created.path("resources").path(0);
        assertThat(application.path("type").asText(), equalTo("AWS::SSO::Application"));
        assertThat(application.path("ARN").asText(), equalTo(applicationArn));
        assertThat(application.has("accountId"), equalTo(false));

        assertThat(failed.path("errorCode").asText(), equalTo("InvalidGrantException"));
        assertThat(failed.has("errorMessage"), equalTo(false));
        assertThat(failed.path("responseElements").isNull(), equalTo(true));
        assertThat(failed.path("requestParameters").path("code").asText(), equalTo(HIDDEN));
        assertThat(failed.has("additionalEventData"), equalTo(false));
    }

    private static void assertUser(JsonNode identity, String account, String userId, String storeArn) {
        assertThat(fieldNames(identity), contains("type", "accountId", "onBehalfOf", "credentialId"));
        assertThat(identity.path("type").asText(), equalTo("IdentityCenterUser"));
        assertThat(identity.path("accountId").asText(), equalTo(account));
        assertThat(identity.path("onBehalfOf").path("userId").asText(), equalTo(userId));
        assertThat(identity.path("onBehalfOf").path("identityStoreArn").asText(), equalTo(storeArn));
        assertThat(identity.path("credentialId").asText(), not(equalTo("")));
    }

    private static void assertPortal(JsonNode record, String account, String userId, String storeArn,
                                     String credentialId) {
        assertUser(record.path("userIdentity"), account, userId, storeArn);
        assertThat(record.path("userIdentity").path("credentialId").asText(), equalTo(credentialId));
        assertThat(record.path("eventType").asText(), equalTo("AwsServiceEvent"));
        assertThat(record.path("managementEvent").asBoolean(), equalTo(true));
        assertThat(record.path("readOnly").asBoolean(), equalTo(true));
        assertThat(record.path("requestParameters").isNull(), equalTo(true));
        assertThat(record.path("responseElements").isNull(), equalTo(true));
        assertThat(record.path("userAgent").asText(), equalTo(CLI));
    }

    private String createUser(String suffix) {
        ObjectNode request = mapper.createObjectNode();
        request.put("IdentityStoreId", ssoAdmin.getIdentityStoreId());
        request.put("UserName", "ct-" + suffix + "@example.com");
        String userId = identityStore.createUser(request).userId();
        cleanup.register(() -> {
            ObjectNode delete = mapper.createObjectNode();
            delete.put("IdentityStoreId", ssoAdmin.getIdentityStoreId());
            delete.put("UserId", userId);
            identityStore.deleteUser(delete);
        });
        return userId;
    }

    private void assign(String userId, String permissionSetName) {
        String instanceArn = ssoAdmin.getInstanceArn();
        ObjectNode permissionSet = mapper.createObjectNode();
        permissionSet.put("InstanceArn", instanceArn);
        permissionSet.put("Name", permissionSetName);
        String permissionSetArn = ssoAdmin.createPermissionSet(permissionSet).arn();
        ObjectNode assignment = mapper.createObjectNode();
        assignment.put("InstanceArn", instanceArn);
        assignment.put("TargetId", MEMBER_ACCOUNT);
        assignment.put("TargetType", "AWS_ACCOUNT");
        assignment.put("PermissionSetArn", permissionSetArn);
        assignment.put("PrincipalId", userId);
        assignment.put("PrincipalType", "USER");
        ssoAdmin.createAssignment(assignment);
    }

    private String createIamApplication(String suffix, String redirectUri) {
        ObjectNode create = mapper.createObjectNode();
        create.put("InstanceArn", ssoAdmin.getInstanceArn());
        create.put("ApplicationProviderArn", "arn:aws:sso::aws:applicationProvider/custom");
        create.put("Name", "ct-iam-" + suffix);
        String applicationArn = ssoAdmin.createApplication(create, "000000000000", "us-east-1").applicationArn();
        cleanup.register(() -> ssoAdmin.deleteApplication(applicationArn));

        ObjectNode authentication = mapper.createObjectNode();
        authentication.put("ApplicationArn", applicationArn);
        authentication.put("AuthenticationMethodType", "IAM");
        ObjectNode policy = authentication.putObject("AuthenticationMethod").putObject("Iam").putObject("ActorPolicy");
        policy.put("Version", "2012-10-17");
        ObjectNode statement = policy.putArray("Statement").addObject();
        statement.put("Effect", "Allow");
        statement.put("Principal", "*");
        statement.put("Action", "sso-oauth:CreateTokenWithIAM");
        statement.put("Resource", "*");
        ssoAdmin.putApplicationAuthenticationMethod(authentication);

        ObjectNode grant = mapper.createObjectNode();
        grant.put("ApplicationArn", applicationArn);
        grant.put("GrantType", "authorization_code");
        grant.putObject("Grant").putObject("AuthorizationCode").putArray("RedirectUris").add(redirectUri);
        ssoAdmin.putApplicationGrant(grant);
        return applicationArn;
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

    private List<JsonNode> records(String bucket, String eventSource) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(DEFAULT_KEY, "s3")).stream()
                .filter(record -> eventSource.equals(record.path("eventSource").asText()))
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

    private static List<String> fieldNames(JsonNode node) {
        List<String> names = new ArrayList<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }
}
