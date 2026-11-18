package io.floci.aws.services.iam;

import io.floci.aws.services.eks.EksOidcService;
import io.floci.aws.testing.AwsTestClients;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import software.amazon.awssdk.auth.credentials.AnonymousCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleWithWebIdentityResponse;
import software.amazon.awssdk.services.sts.model.StsException;

import java.net.URI;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * A web identity trust policy's {@code Condition} is read with every IAM condition operator, through the SDK, against
 * a token Floci's own OIDC issuer mints. {@code {p}} in a condition stands for the provider's key prefix. The token
 * carries {@code sub} and {@code aud} and no {@code amr}, so the cases on {@code amr} are the guide's missing-key
 * rules.
 */
@QuarkusTest
class WebIdentityTrustConditionOperatorsIntegrationTest {

    private static final String ACCOUNT = "000000000000";
    private static final String SUBJECT = "system:serviceaccount:apps:reporting";

    @TestHTTPResource("/")
    URI endpoint;

    @Inject
    IamService iam;

    @Inject
    EksOidcService oidc;

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "{\"StringEquals\":{\"{p}:sub\":\"system:serviceaccount:apps:reporting\"}}|allow",
        "{\"StringEquals\":{\"{p}:sub\":\"system:serviceaccount:apps:other\"}}|AccessDenied",
        "{\"StringEqualsIgnoreCase\":{\"{p}:sub\":\"SYSTEM:SERVICEACCOUNT:APPS:REPORTING\"}}|allow",
        "{\"StringNotEquals\":{\"{p}:amr\":\"authenticated\"}}|allow",
        "{\"StringLike\":{\"{p}:amr\":\"*\"}}|AccessDenied",
        "{\"StringLikeIfExists\":{\"{p}:amr\":\"authenticated\"}}|allow",
        "{\"Null\":{\"{p}:amr\":\"true\"}}|allow",
        "{\"Null\":{\"{p}:sub\":\"false\"}}|allow",
        "{\"ForAnyValue:StringEquals\":{\"{p}:amr\":[\"authenticated\"]}}|AccessDenied",
        "{\"ForAllValues:StringEquals\":{\"{p}:amr\":[\"authenticated\"]}}|allow",
        "{\"ForAnyValue:StringLike\":{\"{p}:aud\":[\"sts.*\"]}}|allow",
        "{\"DateGreaterThan\":{\"aws:CurrentTime\":\"2020-01-01T00:00:00Z\"}}|allow",
        "{\"DateLessThan\":{\"aws:CurrentTime\":\"2020-01-01T00:00:00Z\"}}|AccessDenied"
    })
    void trustPolicyConditionsAreReadWithEveryOperator(String condition, String expected) {
        String name = "web-operators-" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        String issuer = oidc.newIssuerUrl("us-east-1");
        String prefix = issuer.substring("https://".length());
        String trust = "{\"Version\":\"2012-10-17\",\"Statement\":{\"Effect\":\"Allow\",\"Principal\":{\"Federated\":\""
                + "arn:aws:iam::" + ACCOUNT + ":oidc-provider/" + prefix
                + "\"},\"Action\":\"sts:AssumeRoleWithWebIdentity\",\"Condition\":"
                + condition.replace("{p}", prefix) + "}}";
        try (IamClient admin = AwsTestClients.create(IamClient.builder(), ACCOUNT, Region.US_EAST_1, endpoint);
             StsClient sts = StsClient.builder().endpointOverride(endpoint).region(Region.US_EAST_1)
                     .credentialsProvider(AnonymousCredentialsProvider.create()).build()) {
            String roleArn = admin.createRole(b -> b.roleName(name).assumeRolePolicyDocument(trust)).role().arn();
            try {
                String token = oidc.mintServiceAccountToken(name, issuer, "apps", "reporting",
                        "sts.amazonaws.com", 3600);
                if ("allow".equals(expected)) {
                    AssumeRoleWithWebIdentityResponse response = sts.assumeRoleWithWebIdentity(b -> b
                            .roleArn(roleArn).roleSessionName("operators").webIdentityToken(token));
                    assertEquals(SUBJECT, response.subjectFromWebIdentityToken());
                    iam.unregisterSession(ACCOUNT, response.credentials().accessKeyId());
                } else {
                    StsException error = assertThrows(StsException.class, () -> sts.assumeRoleWithWebIdentity(b -> b
                            .roleArn(roleArn).roleSessionName("operators").webIdentityToken(token)));
                    assertEquals(expected, error.awsErrorDetails().errorCode());
                    assertEquals(403, error.statusCode());
                }
            } finally {
                try {
                    oidc.deleteKey(name);
                } finally {
                    admin.deleteRole(b -> b.roleName(name));
                }
            }
        }
    }
}
