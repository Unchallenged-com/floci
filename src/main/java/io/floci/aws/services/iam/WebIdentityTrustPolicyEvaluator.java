package io.floci.aws.services.iam;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.aws.core.common.IamConditionContextResolver;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Evaluates a role's trust policy for {@code sts:AssumeRoleWithWebIdentity}, matching the
 * {@code Federated} principal and the {@code Condition} block that pins an OIDC subject and
 * audience.
 *
 * <p>Separate from {@link AssumeRolePolicyEvaluator} on purpose. That evaluator serves the
 * {@code sts:AssumeRole} path, hardcodes that action, reads only {@code Principal.AWS}, and ignores
 * conditions — widening it would risk regressing a path that already works. The two are
 * complementary: this one only ever considers federated principals.
 *
 * <p>The {@code Condition} is read by {@link IamPolicyEvaluator#conditionMatches}, with the
 * operators every other policy is read with. Its string operators compare case-sensitively, so an
 * OIDC subject like {@code system:serviceaccount:apps:My-Account} does not match a policy naming
 * {@code my-account}.
 */
@ApplicationScoped
public class WebIdentityTrustPolicyEvaluator {

    private static final Logger LOG = Logger.getLogger(WebIdentityTrustPolicyEvaluator.class);
    private static final String WEB_IDENTITY_ACTION = "sts:assumerolewithwebidentity";

    private final ObjectMapper objectMapper;
    private final IamPolicyEvaluator policyEvaluator;

    @Inject
    public WebIdentityTrustPolicyEvaluator(ObjectMapper objectMapper, IamPolicyEvaluator policyEvaluator) {
        this.objectMapper = objectMapper;
        this.policyEvaluator = policyEvaluator;
    }

    /**
     * Returns true if {@code trustPolicyDocument} allows a web-identity token from
     * {@code oidcProviderArn} with the given claim context to assume the role.
     *
     * <p>{@code claims} holds the OIDC condition context keyed <em>without</em> the provider
     * prefix — {@code sub}, {@code aud} — which this evaluator resolves against policy keys of the
     * form {@code <provider-host-and-path>:sub}, so a key naming another provider is absent. The
     * context also carries the time of the request, which the IAM User Guide says "is always
     * included in the request context". An explicit {@code Deny} wins over any {@code Allow}, per
     * AWS precedence.
     */
    public boolean allows(String trustPolicyDocument, String oidcProviderArn, String issuerKeyPrefix,
                          Map<String, List<String>> claims) {
        if (trustPolicyDocument == null || trustPolicyDocument.isBlank()) {
            return false;
        }
        JsonNode root;
        try {
            root = objectMapper.readTree(trustPolicyDocument);
        } catch (JsonProcessingException e) {
            LOG.warnv("Failed to parse web-identity trust policy: {0}", e.getMessage());
            return false;
        }
        JsonNode statements = root.path("Statement");
        if (!TrustPolicyStatements.wellFormed(statements)) {
            return false;
        }
        String version = root.path("Version").asText(null);
        Map<String, List<String>> context = conditionContext(issuerKeyPrefix, claims);

        boolean allow = false;
        if (statements.isArray()) {
            for (JsonNode stmt : statements) {
                switch (evaluate(stmt, oidcProviderArn, context, version)) {
                    case DENY -> { return false; }
                    case ALLOW -> allow = true;
                    case NO_MATCH -> { }
                }
            }
            return allow;
        }
        if (statements.isObject()) {
            return evaluate(statements, oidcProviderArn, context, version) == Match.ALLOW;
        }
        return false;
    }

    private enum Match { ALLOW, DENY, NO_MATCH }

    private static Map<String, List<String>> conditionContext(String issuerKeyPrefix,
                                                              Map<String, List<String>> claims) {
        Map<String, List<String>> context = new LinkedHashMap<>();
        claims.forEach((name, values) -> context.put(issuerKeyPrefix + ":" + name, values));
        IamConditionContextResolver.putRequestTime(context);
        return context;
    }

    private Match evaluate(JsonNode stmt, String oidcProviderArn, Map<String, List<String>> context,
                           String version) {
        if (!actionApplies(stmt)) {
            return Match.NO_MATCH;
        }
        if (!matchesFederatedPrincipal(stmt.get("Principal"), oidcProviderArn)) {
            return Match.NO_MATCH;
        }
        if (!policyEvaluator.conditionMatches(stmt.get("Condition"), context, version)) {
            return Match.NO_MATCH;
        }
        return TrustPolicyStatements.denies(stmt) ? Match.DENY : Match.ALLOW;
    }

    /**
     * True when the statement's action element covers {@code sts:AssumeRoleWithWebIdentity}. Action
     * names are case-insensitive in AWS policy documents, and wildcards are honoured.
     */
    private boolean actionApplies(JsonNode stmt) {
        JsonNode action = stmt.get("Action");
        if (action != null) {
            return matchesAction(action);
        }
        JsonNode notAction = stmt.get("NotAction");
        if (notAction != null) {
            return !matchesAction(notAction);
        }
        return false;
    }

    private boolean matchesAction(JsonNode actionNode) {
        if (actionNode.isTextual()) {
            return IamPolicyEvaluator.globMatches(actionNode.asText(), WEB_IDENTITY_ACTION);
        }
        if (actionNode.isArray()) {
            for (JsonNode entry : actionNode) {
                if (entry.isTextual()
                        && IamPolicyEvaluator.globMatches(entry.asText(), WEB_IDENTITY_ACTION)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Matches {@code Principal.Federated} against the OIDC provider ARN. Only the federated
     * principal type can match a web-identity caller — an {@code AWS} principal never does.
     */
    private boolean matchesFederatedPrincipal(JsonNode principalNode, String oidcProviderArn) {
        if (principalNode == null || oidcProviderArn == null) {
            return false;
        }
        if (principalNode.isTextual()) {
            return "*".equals(principalNode.asText());
        }
        if (!principalNode.isObject()) {
            return false;
        }
        JsonNode federated = principalNode.get("Federated");
        if (federated == null) {
            return false;
        }
        if (federated.isTextual()) {
            return federatedMatches(federated.asText(), oidcProviderArn);
        }
        if (federated.isArray()) {
            for (JsonNode entry : federated) {
                if (entry.isTextual() && federatedMatches(entry.asText(), oidcProviderArn)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean federatedMatches(String declared, String oidcProviderArn) {
        return "*".equals(declared) || declared.equals(oidcProviderArn);
    }
}
