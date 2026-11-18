package io.floci.aws.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The trust policies of {@code sts:AssumeRoleWithWebIdentity} and {@code sts:AssumeRoleWithSAML} read their
 * {@code Condition} with the operators every other policy is read with, as the IAM User Guide's condition operator
 * reference describes them. Each case is one of the guide's evaluation tables, written against a key the federated
 * caller carries ({@code sub}) and one it does not ({@code missing}).
 */
class FederatedTrustConditionOperatorsTest {

    private static final String ACCOUNT = "111111111111";
    private static final String OIDC_PREFIX = "oidc.eks.us-east-1.amazonaws.com/id/ABCDEF0123456789";
    private static final String OIDC_PROVIDER = "arn:aws:iam::" + ACCOUNT + ":oidc-provider/" + OIDC_PREFIX;
    private static final String SAML_PROVIDER = "arn:aws:iam::" + ACCOUNT + ":saml-provider/corp";
    private static final String SUBJECT = "system:serviceaccount:apps:reporting";

    private final ObjectMapper mapper = new ObjectMapper();
    private final IamPolicyEvaluator policies = new IamPolicyEvaluator(mapper);
    private final WebIdentityTrustPolicyEvaluator webIdentity = new WebIdentityTrustPolicyEvaluator(mapper, policies);
    private final SAMLTrustPolicyEvaluator saml = new SAMLTrustPolicyEvaluator(mapper, policies);

    /** A federated path, with the principal and action a statement names to reach it and its key namespace. */
    enum Path {
        WEB_IDENTITY("{\"Federated\":\"" + OIDC_PROVIDER + "\"}", "sts:AssumeRoleWithWebIdentity", OIDC_PREFIX),
        SAML("{\"Federated\":\"" + SAML_PROVIDER + "\"}", "sts:AssumeRoleWithSAML", "saml");

        private final String principal;
        private final String action;
        private final String namespace;

        Path(String principal, String action, String namespace) {
            this.principal = principal;
            this.action = action;
            this.namespace = namespace;
        }

        /** The policy key for the claim {@code name} on this path, such as {@code saml:sub}. */
        String key(String name) {
            return namespace + ":" + name;
        }

        String statement(String effect, String condition) {
            return "{\"Effect\":\"" + effect + "\",\"Principal\":" + principal + ",\"Action\":\"" + action
                    + "\",\"Condition\":" + condition + "}";
        }
    }

    private boolean allows(Path path, String... statements) {
        String document = "{\"Version\":\"2012-10-17\",\"Statement\":[" + String.join(",", statements) + "]}";
        Map<String, List<String>> claims = Map.of("sub", List.of(SUBJECT));
        return switch (path) {
            case WEB_IDENTITY -> webIdentity.allows(document, OIDC_PROVIDER, OIDC_PREFIX, claims);
            case SAML -> saml.allows(document, SAML_PROVIDER, claims);
        };
    }

    private boolean allowedWhen(Path path, String operator, String key, String values) {
        return allows(path, path.statement("Allow", "{\"" + operator + "\":{\"" + key + "\":" + values + "}}"));
    }

    // "If the key that you specify in a policy condition is not present in the request context, the values do not
    // match and the condition is false. If the policy condition requires that the key is not matched, such as
    // StringNotLike or ArnNotLike, and the right key is not present, the condition is true."

    @ParameterizedTest
    @EnumSource(Path.class)
    void aMissingKeyMatchesNoPositiveOperator(Path path) {
        assertFalse(allowedWhen(path, "StringEquals", path.key("missing"), "\"x\""));
        assertFalse(allowedWhen(path, "StringLike", path.key("missing"), "\"*\""));
    }

    @ParameterizedTest
    @EnumSource(Path.class)
    void aMissingKeySatisfiesANegatedOperator(Path path) {
        assertTrue(allowedWhen(path, "StringNotEquals", path.key("missing"), "\"x\""));
        assertTrue(allowedWhen(path, "StringNotLike", path.key("missing"), "\"x*\""));
        assertTrue(allowedWhen(path, "StringNotEqualsIgnoreCase", path.key("missing"), "\"x\""));
    }

    @ParameterizedTest
    @EnumSource(Path.class)
    void aDenyWithANegatedOperatorAppliesWhenTheKeyIsMissing(Path path) {
        String allow = "{\"Effect\":\"Allow\",\"Principal\":" + path.principal + ",\"Action\":\"" + path.action + "\"}";
        assertFalse(allows(path, allow,
                path.statement("Deny", "{\"StringNotEqualsIfExists\":{\"" + path.key("missing") + "\":\"x\"}}")));
        assertFalse(allows(path, allow,
                path.statement("Deny", "{\"StringNotEquals\":{\"" + path.key("missing") + "\":\"x\"}}")));
    }

    @ParameterizedTest
    @EnumSource(Path.class)
    void theNegatedOperatorsCompareThePresentValue(Path path) {
        assertFalse(allowedWhen(path, "StringNotEquals", path.key("sub"), "\"" + SUBJECT + "\""));
        assertTrue(allowedWhen(path, "StringNotEquals", path.key("sub"), "[\"a\",\"b\"]"));
        assertFalse(allowedWhen(path, "StringNotLike", path.key("sub"), "\"system:serviceaccount:apps:*\""));
    }

    @ParameterizedTest
    @EnumSource(Path.class)
    void stringEqualsIgnoreCaseIgnoresCaseAndStringEqualsDoesNot(Path path) {
        assertTrue(allowedWhen(path, "StringEqualsIgnoreCase", path.key("sub"), "\"" + SUBJECT.toUpperCase() + "\""));
        assertFalse(allowedWhen(path, "StringEquals", path.key("sub"), "\"" + SUBJECT.toUpperCase() + "\""));
    }

    // "If the condition key is present in the context of the request, process the key as specified in the policy.
    // If the key is not present, evaluate the condition element as true."

    @ParameterizedTest
    @EnumSource(Path.class)
    void ifExistsMatchesAMissingKeyAndComparesAPresentOne(Path path) {
        assertTrue(allowedWhen(path, "StringLikeIfExists", path.key("missing"), "[\"t1.*\",\"t2.*\"]"));
        assertTrue(allowedWhen(path, "StringLikeIfExists", path.key("sub"), "\"system:serviceaccount:*\""));
        assertFalse(allowedWhen(path, "StringLikeIfExists", path.key("sub"), "\"system:node:*\""));
    }

    // Null: "use either true (the key doesn't exist — it is null) or false (the key exists and its value is not
    // null)."

    @ParameterizedTest
    @EnumSource(Path.class)
    void nullTestsWhetherTheKeyIsPresent(Path path) {
        assertTrue(allowedWhen(path, "Null", path.key("missing"), "\"true\""));
        assertFalse(allowedWhen(path, "Null", path.key("missing"), "\"false\""));
        assertTrue(allowedWhen(path, "Null", path.key("sub"), "\"false\""));
        assertFalse(allowedWhen(path, "Null", path.key("sub"), "\"true\""));
    }

    // ForAllValues: "It also returns true if there are no context keys in the request." ForAnyValue: "For no
    // matching context key or if the key does not exist, the condition returns false."

    @ParameterizedTest
    @EnumSource(Path.class)
    void theSetOperatorsFollowTheirOwnRuleForAMissingKey(Path path) {
        assertTrue(allowedWhen(path, "ForAllValues:StringEquals", path.key("missing"), "[\"a\",\"b\"]"));
        assertFalse(allowedWhen(path, "ForAnyValue:StringEquals", path.key("missing"), "[\"a\",\"b\"]"));
        assertFalse(allows(path, path.statement("Allow", "{\"ForAllValues:StringEquals\":{\"" + path.key("missing")
                + "\":[\"a\",\"b\"]},\"Null\":{\"" + path.key("missing") + "\":\"false\"}}")));
    }

    @ParameterizedTest
    @EnumSource(Path.class)
    void theSetOperatorsCompareThePresentValues(Path path) {
        assertTrue(allowedWhen(path, "ForAnyValue:StringEquals", path.key("sub"), "[\"other\",\"" + SUBJECT + "\"]"));
        assertFalse(allowedWhen(path, "ForAnyValue:StringEquals", path.key("sub"), "[\"other\"]"));
        assertTrue(allowedWhen(path, "ForAllValues:StringLike", path.key("sub"), "[\"system:serviceaccount:*\"]"));
        assertFalse(allowedWhen(path, "ForAllValues:StringNotLike", path.key("sub"), "[\"system:serviceaccount:*\"]"));
    }

    // aws:CurrentTime and aws:EpochTime: "This key is always included in the request context."

    @ParameterizedTest
    @EnumSource(Path.class)
    void theDateOperatorsCompareTheTimeOfTheRequest(Path path) {
        Instant now = Instant.now();
        assertTrue(allowedWhen(path, "DateGreaterThan", "aws:CurrentTime", "\"2020-01-01T00:00:01Z\""));
        assertFalse(allowedWhen(path, "DateLessThan", "aws:CurrentTime", "\"2020-01-01T00:00:01Z\""));
        assertTrue(allowedWhen(path, "DateLessThan", "aws:CurrentTime", "\"" + now.plusSeconds(3600) + "\""));
        assertTrue(allowedWhen(path, "DateLessThan", "aws:EpochTime", Long.toString(now.plusSeconds(3600).getEpochSecond())));
    }

    @ParameterizedTest
    @EnumSource(Path.class)
    void theNumericOperatorsCompareANumber(Path path) {
        long now = Instant.now().getEpochSecond();
        assertTrue(allowedWhen(path, "NumericGreaterThan", "aws:EpochTime", "\"" + (now - 3600) + "\""));
        assertFalse(allowedWhen(path, "NumericGreaterThan", "aws:EpochTime", "\"" + (now + 3600) + "\""));
    }

    @ParameterizedTest
    @EnumSource(Path.class)
    void everyBlockAndEveryKeyMustMatch(Path path) {
        assertFalse(allows(path, path.statement("Allow", "{\"StringEquals\":{\"" + path.key("sub") + "\":\"" + SUBJECT
                + "\"},\"DateLessThan\":{\"aws:CurrentTime\":\"2020-01-01T00:00:00Z\"}}")));
        assertTrue(allows(path, path.statement("Allow", "{\"StringEquals\":{\"" + path.key("sub") + "\":\"" + SUBJECT
                + "\"},\"DateGreaterThan\":{\"aws:CurrentTime\":\"2020-01-01T00:00:00Z\"}}")));
    }

    @ParameterizedTest
    @EnumSource(Path.class)
    void aClaimIsReadOnlyUnderItsOwnNamespace(Path path) {
        assertFalse(allowedWhen(path, "StringEquals", "other.example.com:sub", "\"" + SUBJECT + "\""));
        assertTrue(allowedWhen(path, "StringEquals", path.key("sub").toUpperCase(), "\"" + SUBJECT + "\""));
    }

    @ParameterizedTest
    @EnumSource(Path.class)
    void anOperatorIamDoesNotDefineMatchesNothing(Path path) {
        assertFalse(allowedWhen(path, "StringMatches", path.key("sub"), "\"" + SUBJECT + "\""));
    }
}
