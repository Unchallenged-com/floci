package io.floci.aws.services.iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.aws.core.common.IamConditionContextResolver;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Evaluates the federated principal and SAML action in a role trust policy, and its
 * {@code Condition} with {@link IamPolicyEvaluator#conditionMatches}, the operators every other
 * policy is read with.
 */
@ApplicationScoped
public class SAMLTrustPolicyEvaluator {
    private static final String SAML_KEY_PREFIX = "saml:";
    private final ObjectMapper mapper;
    private final IamPolicyEvaluator policyEvaluator;

    @Inject
    public SAMLTrustPolicyEvaluator(ObjectMapper mapper, IamPolicyEvaluator policyEvaluator) {
        this.mapper = mapper;
        this.policyEvaluator = policyEvaluator;
    }

    /**
     * {@code claims} holds the assertion's values keyed by their name in the {@code saml:}
     * namespace without the prefix ({@code sub}, {@code iss}), which a policy reads as
     * {@code saml:sub}. The context also carries the time of the request, which the IAM User Guide
     * says "is always included in the request context".
     */
    public boolean allows(String document, String providerArn, Map<String, List<String>> claims) {
        try {
            JsonNode root = mapper.readTree(document);
            JsonNode statements = root.path("Statement");
            if (!TrustPolicyStatements.wellFormed(statements)) {
                return false;
            }
            String version = root.path("Version").asText(null);
            Map<String, List<String>> context = conditionContext(claims);
            if (statements.isArray()) {
                boolean allowed = false;
                for (JsonNode statement : statements) {
                    int result = evaluate(statement, providerArn, context, version);
                    if (result < 0) {
                        return false;
                    }
                    if (result > 0) {
                        allowed = true;
                    }
                }
                return allowed;
            }
            return statements.isObject() && evaluate(statements, providerArn, context, version) > 0;
        } catch (Exception e) {
            return false;
        }
    }

    private static Map<String, List<String>> conditionContext(Map<String, List<String>> claims) {
        Map<String, List<String>> context = new LinkedHashMap<>();
        claims.forEach((name, values) -> context.put(SAML_KEY_PREFIX + name, values));
        IamConditionContextResolver.putRequestTime(context);
        return context;
    }

    private int evaluate(JsonNode statement, String providerArn, Map<String, List<String>> context,
                         String version) {
        if (!actionApplies(statement) || !principal(statement.path("Principal"), providerArn)
                || !policyEvaluator.conditionMatches(statement.get("Condition"), context, version)) {
            return 0;
        }
        return TrustPolicyStatements.denies(statement) ? -1 : 1;
    }

    private boolean actionApplies(JsonNode statement) {
        JsonNode action = statement.get("Action");
        if (action != null) {
            return action(action);
        }
        JsonNode notAction = statement.get("NotAction");
        return notAction != null && !action(notAction);
    }

    private boolean action(JsonNode node) {
        if (node.isTextual()) {
            return matches(node.asText());
        }
        if (node.isArray()) {
            for (JsonNode value : node) {
                if (value.isTextual() && matches(value.asText())) {
                    return true;
                }
            }
        }
        return false;
    }
    private boolean matches(String action) {
        String regex = action.replace(".", "\\.").replace("*", ".*").replace("?", ".");
        return "sts:AssumeRoleWithSAML".matches("(?i)^" + regex + "$");
    }
    private boolean principal(JsonNode node, String providerArn) {
        JsonNode federated = node.isObject() ? node.get("Federated") : null;
        if (federated == null) {
            return "*".equals(node.asText());
        }
        if (federated.isTextual()) {
            return "*".equals(federated.asText()) || providerArn.equals(federated.asText());
        }
        if (federated.isArray()) {
            for (JsonNode value : federated) {
                if (value.isTextual()
                        && ("*".equals(value.asText()) || providerArn.equals(value.asText()))) {
                    return true;
                }
            }
        }
        return false;
    }
}
