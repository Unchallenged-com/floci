package io.floci.aws.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.nullValue;

class StsCloudTrailEventsTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static MultivaluedMap<String, String> params(String... pairs) {
        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            params.putSingle(pairs[i], pairs[i + 1]);
        }
        return params;
    }

    @ParameterizedTest
    @CsvSource({"AssumeRole,true,true", "AssumeRoleWithSAML,true,true", "AssumeRoleWithWebIdentity,true,true",
            "AssumeRoot,false,true", "GetFederationToken,false,true", "GetSessionToken,false,true",
            "GetCallerIdentity,true,false", "GetAccessKeyInfo,true,false", "DecodeAuthorizationMessage,true,false",
            "GetWebIdentityToken,false,false"})
    void readOnlyAndTheResultFollowTheUserGuidesTable(String action, boolean readOnly, boolean recordsResult) {
        assertThat(StsCloudTrailEvents.isReadOnly(action), equalTo(readOnly));
        assertThat(StsCloudTrailEvents.recordsResult(action), equalTo(recordsResult));
    }

    @Test
    void theMfaCodeIsLeftOutAndTheDeviceKept() {
        ObjectNode read = StsCloudTrailEvents.requestParameters("AssumeRole", params("Action", "AssumeRole",
                "RoleArn", "arn:aws:iam::111122223333:role/ops", "RoleSessionName", "night",
                "SerialNumber", "arn:aws:iam::111122223333:mfa/alice", "TokenCode", "123456",
                "DurationSeconds", "1800"), null);
        assertThat(read.path("serialNumber").asText(), equalTo("arn:aws:iam::111122223333:mfa/alice"));
        assertThat(read.has("tokenCode"), equalTo(false));
        assertThat(read.path("durationSeconds").isIntegralNumber(), equalTo(true));
    }

    @Test
    void theFederatedCallsLeaveTheirTokenAndAssertionOut() {
        ObjectNode web = StsCloudTrailEvents.requestParameters("AssumeRoleWithWebIdentity",
                params("RoleArn", "arn:aws:iam::111122223333:role/web", "RoleSessionName", "app",
                        "WebIdentityToken", "eyJhbGciOiJSUzI1NiJ9.e30.c2ln"), null);
        assertThat(web.has("webIdentityToken"), equalTo(false));
        assertThat(web.path("roleSessionName").asText(), equalTo("app"));
        ObjectNode saml = StsCloudTrailEvents.requestParameters("AssumeRoleWithSAML",
                params("RoleArn", "arn:aws:iam::111122223333:role/saml",
                        "PrincipalArn", "arn:aws:iam::111122223333:saml-provider/idp", "SAMLAssertion", "PHNhbWw+"),
                null);
        assertThat(saml.has("sAMLAssertion"), equalTo(false));
        assertThat(saml.path("principalArn").asText(), equalTo("arn:aws:iam::111122223333:saml-provider/idp"));
    }

    @Test
    void credentialsExpireInIso8601ToTheSecondWithoutTheirSecret() {
        String xml = """
                <AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult>
                  <Credentials><AccessKeyId>ASIAIOSFODNN7EXAMPLE</AccessKeyId>
                    <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</SecretAccessKey>
                    <SessionToken>FwoGZXIvYXdzEXAMPLE</SessionToken>
                    <Expiration>2026-09-11T19:55:38.512Z</Expiration></Credentials>
                  <AssumedRoleUser><Arn>arn:aws:sts::111122223333:assumed-role/ops/night</Arn>
                    <AssumedRoleId>AROA123456789EXAMPLE:night</AssumedRoleId></AssumedRoleUser>
                  <PackedPolicySize>0</PackedPolicySize>
                </AssumeRoleResult></AssumeRoleResponse>""";
        ObjectNode result = StsCloudTrailEvents.result("AssumeRole", xml);
        assertThat(result.path("credentials").path("expiration").asText(), equalTo("2026-09-11T19:55:38Z"));
        assertThat(result.path("credentials").has("secretAccessKey"), equalTo(false));
        assertThat(result.path("packedPolicySize").isNumber(), equalTo(true));
    }

    @Test
    void anAuthorizationRefusalHasNoRequestParameters() {
        assertThat(StsCloudTrailEvents.requestParameters("AssumeRole",
                params("RoleArn", "arn:aws:iam::111122223333:role/ops", "RoleSessionName", "night"), "AccessDenied"),
                nullValue());
    }

    @Test
    void aSamlRoleSessionNamesTheRoleAndTheProvider() {
        ArrayNode resources = StsCloudTrailEvents.resources("AssumeRoleWithSAML",
                params("RoleArn", "arn:aws:iam::111122223333:role/saml",
                        "PrincipalArn", "arn:aws:iam::111122223333:saml-provider/idp"));
        assertThat(resources.size(), equalTo(2));
        assertThat(resources.get(0).path("type").asText(), equalTo("AWS::IAM::Role"));
        assertThat(resources.get(0).path("accountId").asText(), equalTo("111122223333"));
        assertThat(resources.get(1).path("type").asText(), equalTo("AWS::IAM::SAMLProvider"));
        assertThat(resources.get(1).path("ARN").asText(), equalTo("arn:aws:iam::111122223333:saml-provider/idp"));
        assertThat(StsCloudTrailEvents.resources("GetSessionToken", params()), nullValue());
    }

    @Test
    void aWebIdentityCallerIsNamedUnderItsProviderAndAudience() {
        ObjectNode result = MAPPER.createObjectNode()
                .put("provider", "https://issuer.example.com/tenant")
                .put("audience", "sts.amazonaws.com")
                .put("subjectFromWebIdentityToken", "user-42");
        ObjectNode caller = StsCloudTrailEvents.federatedCaller("AssumeRoleWithWebIdentity",
                params("RoleArn", "arn:aws:iam::111122223333:role/web"), result);
        String provider = "arn:aws:iam::111122223333:oidc-provider/issuer.example.com/tenant";
        assertThat(caller.path("type").asText(), equalTo("WebIdentityUser"));
        assertThat(caller.path("identityProvider").asText(), equalTo(provider));
        assertThat(caller.path("principalId").asText(), equalTo(provider + ":sts.amazonaws.com:user-42"));
        assertThat(caller.path("userName").asText(), equalTo("user-42"));
    }

    @Test
    void aSamlCallerIsNamedUnderItsNameQualifier() {
        ObjectNode result = MAPPER.createObjectNode().put("subject", "alice").put("nameQualifier", "bdGOnTe=");
        ObjectNode caller = StsCloudTrailEvents.federatedCaller("AssumeRoleWithSAML", params(), result);
        assertThat(caller.path("type").asText(), equalTo("SAMLUser"));
        assertThat(caller.path("principalId").asText(), equalTo("bdGOnTe=:alice"));
        assertThat(caller.path("userName").asText(), equalTo("alice"));
        assertThat(caller.path("identityProvider").asText(), equalTo("bdGOnTe="));
    }

    @Test
    void theSessionTokenSizeAndItsShareOfTheLimitAreRecordedRoundedDown() {
        ObjectNode assumed = MAPPER.createObjectNode().put("packedPolicySize", 0);
        assumed.putObject("credentials").put("sessionToken", "a".repeat(688));
        StsCloudTrailEvents.sessionTokenSize("AssumeRole", assumed);
        assertThat(assumed.path("sessionTokenSize").asInt(), equalTo(688));
        assertThat(assumed.path("sessionTokenUtilization").asInt(), equalTo(16));
        assertThat(assumed.path("packedPolicySize").asInt(), equalTo(16));

        ObjectNode session = MAPPER.createObjectNode();
        session.putObject("credentials").put("sessionToken", "a".repeat(2532));
        StsCloudTrailEvents.sessionTokenSize("GetSessionToken", session);
        assertThat(session.path("sessionTokenUtilization").asInt(), equalTo(61));
        assertThat(session.has("packedPolicySize"), equalTo(false));
    }

    @Test
    void requestDetailsNameTheEndpointThatServedTheCall() {
        ObjectNode regional = StsCloudTrailEvents.additionalEventData("GetCallerIdentity", "localhost:4566",
                "eu-west-3", 1789155634441L);
        assertThat(regional.path("RequestDetails").path("endpointType").asText(), equalTo("regional"));
        assertThat(regional.path("RequestDetails").path("awsServingRegion").asText(), equalTo("eu-west-3"));
        ObjectNode global = StsCloudTrailEvents.additionalEventData("AssumeRole", "sts.amazonaws.com", "us-east-1",
                1789155634441L);
        assertThat(global.path("RequestDetails").path("endpointType").asText(), equalTo("global"));
        assertThat(global.has("identityProviderConnectionVerificationMethod"), equalTo(false));
        assertThat(new String(Base64.getDecoder().decode(regional.path("ExtendedRequestId").asText()),
                StandardCharsets.UTF_8), matchesPattern("1:eu-west-3:S:1789155634441:R:[A-Za-z0-9]{8}"));
        assertThat(new String(Base64.getDecoder().decode(global.path("ExtendedRequestId").asText()),
                StandardCharsets.UTF_8), matchesPattern("1:us-east-1:S:1789155634441:G:[A-Za-z0-9]{8}"));
        assertThat(StsCloudTrailEvents.additionalEventData("AssumeRoleWithWebIdentity", null, "us-east-1", 0L)
                .path("identityProviderConnectionVerificationMethod").asText(), equalTo("IAMTrustStore"));
    }

    @Test
    void aSamlCallRecordsTheAssertionIdAndTheSessionName() {
        String assertion = Base64.getEncoder().encodeToString(
                ("<saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_c0046cEXAMPLE\""
                        + " Version=\"2.0\"/>").getBytes(StandardCharsets.UTF_8));
        ObjectNode result = MAPPER.createObjectNode();
        result.putObject("assumedRoleUser").put("arn", "arn:aws:sts::111122223333:assumed-role/saml/alice");
        ObjectNode read = StsCloudTrailEvents.samlRequestParameters(
                StsCloudTrailEvents.requestParameters("AssumeRoleWithSAML",
                        params("RoleArn", "arn:aws:iam::111122223333:role/saml", "SAMLAssertion", assertion), null),
                params("SAMLAssertion", assertion), result);
        assertThat(read.path("sAMLAssertionID").asText(), equalTo("_c0046cEXAMPLE"));
        assertThat(read.path("roleSessionName").asText(), equalTo("alice"));
        assertThat(read.has("sAMLAssertion"), equalTo(false));
    }
}
