package io.floci.aws.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AccountResolver;
import io.floci.aws.core.common.AwsArnUtils;
import io.floci.aws.core.common.RequestContext;
import io.floci.aws.core.common.ServicePrincipals;
import io.floci.aws.core.common.XmlParser;
import io.floci.aws.services.cloudtrail.CloudTrailService;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Records STS API calls as CloudTrail management events, as the IAM User Guide says CloudTrail
 * does: "CloudTrail logs all authenticated API requests to IAM and AWS STS API operations"
 * (https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html). The record follows
 * that page's STS events: {@code eventSource} {@code sts.amazonaws.com}, {@code awsRegion} the Region
 * the request was signed for, {@code requestParameters} the request's members as STS's model types
 * them, and {@code resources} the role a role is assumed from.
 *
 * <p>{@code readOnly} and {@code responseElements} follow the page's table: {@code AssumeRole},
 * {@code AssumeRoleWithSAML} and {@code AssumeRoleWithWebIdentity} are read-only and still carry
 * "the full responseElements except secretAccessKey"; {@code AssumeRoot},
 * {@code GetFederationToken} and {@code GetSessionToken} are not read-only and carry them too.
 * {@code GetWebIdentityToken} is not read-only either, as AWS records it. Any other call is
 * read-only, as CloudTrail "considers an action read-only if it does not have any mutating effect
 * on a resource", and "When logging a read-only event, CloudTrail redacts the responseElements
 * information". A refusal, which AWS records as {@code AccessDenied} with the caller, the action
 * and the role, carries {@code "requestParameters": null} and no {@code resources}; any other error
 * keeps the request's members.
 *
 * <p>The two calls no access key signs, {@code AssumeRoleWithSAML} and
 * {@code AssumeRoleWithWebIdentity}, name the federated caller as the page's examples do, a
 * {@code SAMLUser} or a {@code WebIdentityUser}. They are recorded once STS has accepted the
 * assertion or token: "some non-authenticated AWS STS requests might not be logged because they do
 * not meet the minimum expectation of being sufficiently valid to be trusted as a legitimate
 * request".
 */
@ApplicationScoped
public class StsCloudTrailEvents {

    private static final Logger LOG = Logger.getLogger(StsCloudTrailEvents.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String EVENT_SOURCE = ServicePrincipals.of("sts");

    /**
     * The calls recorded as not read-only: the page's table names the first three, and AWS records
     * {@code GetWebIdentityToken} the same way.
     */
    private static final Set<String> WRITES =
            Set.of("AssumeRoot", "GetFederationToken", "GetSessionToken", "GetWebIdentityToken");

    /** The read-only calls whose record still carries their result, from the same table. */
    private static final Set<String> READ_ONLY_WITH_RESULT =
            Set.of("AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity");

    /**
     * The calls not read-only whose record carries their result, from the same table. The token
     * {@code GetWebIdentityToken} answers with is a bearer credential, so its result is left out.
     */
    private static final Set<String> WRITES_WITH_RESULT =
            Set.of("AssumeRoot", "GetFederationToken", "GetSessionToken");

    /**
     * Request members that carry a secret or a bearer credential. The page's examples carry
     * {@code serialNumber} without the {@code tokenCode} that comes with it, and the federated calls
     * without their assertion or token.
     */
    private static final Set<String> SECRET_REQUEST_MEMBERS =
            Set.of("tokenCode", "sAMLAssertion", "webIdentityToken", "tradeInToken");

    /** Result members STS types as integers: the session token's size and how much of it is used. */
    private static final Pattern NUMBER_MEMBER = Pattern.compile("packedPolicySize|sessionTokenSize"
            + "|sessionTokenUtilization");

    /** Credentials expire as the page's records write it: {@code Feb 12, 2025, 11:16:48 PM}. */
    private static final DateTimeFormatter RECORD_TIMESTAMP =
            DateTimeFormatter.ofPattern("MMM d, yyyy, h:mm:ss a", Locale.US).withZone(ZoneOffset.UTC);

    private static final QueryResultElements RESULTS =
            new QueryResultElements(NUMBER_MEMBER, RECORD_TIMESTAMP, Set.of("secretAccessKey"));

    private final CloudTrailService cloudTrail;
    private final AccountResolver accounts;
    private final RequestContext requestContext;
    private final CurrentVertxRequest currentRequest;

    @Inject
    public StsCloudTrailEvents(CloudTrailService cloudTrail, AccountResolver accounts,
                               RequestContext requestContext, CurrentVertxRequest currentRequest) {
        this.cloudTrail = cloudTrail;
        this.accounts = accounts;
        this.requestContext = requestContext;
        this.currentRequest = currentRequest;
    }

    /** Records the call {@code response} answered; a record that cannot be built is logged, not raised. */
    public void record(String action, MultivaluedMap<String, String> params, String authorization,
                       Response response) {
        if (action == null || !cloudTrail.hasTrails() || response == null
                || !(response.getEntity() instanceof String xml)) {
            return;
        }
        try {
            emit(action, params, authorization, response.getStatus(), xml);
        } catch (RuntimeException e) {
            LOG.warnv(e, "Failed to record STS call {0} in CloudTrail", action);
        }
    }

    private void emit(String action, MultivaluedMap<String, String> params, String authorization, int status,
                      String xml) {
        String errorCode = status >= 400 ? XmlParser.extractFirst(xml, "Code", null) : null;
        if ("UnsupportedOperation".equals(errorCode)) {
            return;
        }
        ObjectNode result = errorCode == null && recordsResult(action) ? RESULTS.read(action, xml) : null;
        ObjectNode federatedCaller = null;
        if (isFederated(action)) {
            federatedCaller = result == null ? null : federatedCaller(action, params, result);
            if (federatedCaller == null) {
                return;
            }
        }
        String errorMessage = errorCode == null ? null : XmlParser.extractFirst(xml, "Message", null);
        HttpServerRequest request = request(currentRequest.getCurrent());
        cloudTrail.emitManagementEvent(new CloudTrailService.ManagementEventInput(EVENT_SOURCE, action,
                requestContext.getRegion(), federatedCaller == null ? accounts.extractAccessKeyId(authorization) : null,
                requestParameters(action, params, errorCode), result, isReadOnly(action), sourceIp(request),
                userAgent(request), XmlParser.extractFirst(xml, "RequestId", null), errorCode, errorMessage, null,
                errorCode == null ? resources(action, params) : null, federatedCaller));
    }

    /**
     * The record of a call IAM enforcement refused before STS ran it, named after the request's
     * {@code Action}, with {@code "requestParameters": null} as AWS records an authorization
     * refusal; null for a request that names none.
     */
    public static CloudTrailService.ManagementEventInput denied(MultivaluedMap<String, String> params,
                                                                String accessKeyId, String region,
                                                                RoutingContext routingContext,
                                                                String errorCode, String errorMessage) {
        String action = params.getFirst("Action");
        if (action == null || action.isBlank()) {
            return null;
        }
        HttpServerRequest request = request(routingContext);
        return new CloudTrailService.ManagementEventInput(EVENT_SOURCE, action, region, accessKeyId, null, null,
                isReadOnly(action), sourceIp(request), userAgent(request), null, errorCode, errorMessage);
    }

    /** Whether CloudTrail records {@code action} as read-only. */
    static boolean isReadOnly(String action) {
        return !WRITES.contains(action);
    }

    /** Whether the record carries the call's result. */
    static boolean recordsResult(String action) {
        return WRITES_WITH_RESULT.contains(action) || READ_ONLY_WITH_RESULT.contains(action);
    }

    /**
     * The request's members, without secrets; null for a call STS refused as not authorized, as
     * AWS records an authorization refusal.
     */
    static ObjectNode requestParameters(String action, MultivaluedMap<String, String> params, String errorCode) {
        if ("AccessDenied".equals(errorCode) || params == null) {
            return null;
        }
        ObjectNode read = StsRequestShapes.read(action, params);
        if (read == null) {
            return null;
        }
        read.remove(SECRET_REQUEST_MEMBERS);
        return read.isEmpty() ? null : read;
    }

    /** The role a role session is assumed from and, for SAML, the provider that vouched for it. */
    static ArrayNode resources(String action, MultivaluedMap<String, String> params) {
        if (!READ_ONLY_WITH_RESULT.contains(action) || params == null) {
            return null;
        }
        String roleArn = params.getFirst("RoleArn");
        if (!AwsArnUtils.isArn(roleArn)) {
            return null;
        }
        ArrayNode resources = MAPPER.createArrayNode();
        resource(resources, roleArn, "AWS::IAM::Role");
        String principalArn = params.getFirst("PrincipalArn");
        if ("AssumeRoleWithSAML".equals(action) && AwsArnUtils.isArn(principalArn)) {
            resource(resources, principalArn, "AWS::IAM::SAMLProvider");
        }
        return resources;
    }

    private static void resource(ArrayNode resources, String arn, String type) {
        resources.addObject()
                .put("accountId", AwsArnUtils.parse(arn).accountId())
                .put("type", type)
                .put("ARN", arn);
    }

    private static boolean isFederated(String action) {
        return "AssumeRoleWithSAML".equals(action) || "AssumeRoleWithWebIdentity".equals(action);
    }

    /**
     * The federated caller as the page's examples name it: a {@code SAMLUser} by the assertion's
     * subject under its name qualifier, a {@code WebIdentityUser} by the token's subject under its
     * provider and audience. Null when the result does not say who it is.
     */
    static ObjectNode federatedCaller(String action, MultivaluedMap<String, String> params, ObjectNode result) {
        ObjectNode identity = MAPPER.createObjectNode();
        if ("AssumeRoleWithSAML".equals(action)) {
            String subject = result.path("subject").asText(null);
            String nameQualifier = result.path("nameQualifier").asText(null);
            if (subject == null || nameQualifier == null) {
                return null;
            }
            identity.put("type", "SAMLUser");
            identity.put("principalId", nameQualifier + ":" + subject);
            identity.put("userName", subject);
            identity.put("identityProvider", nameQualifier);
            return identity;
        }
        String subject = result.path("subjectFromWebIdentityToken").asText(null);
        String audience = result.path("audience").asText(null);
        String provider = oidcProvider(result.path("provider").asText(null), params.getFirst("RoleArn"));
        if (subject == null || audience == null || provider == null) {
            return null;
        }
        identity.put("type", "WebIdentityUser");
        identity.put("principalId", provider + ":" + audience + ":" + subject);
        identity.put("userName", subject);
        identity.put("identityProvider", provider);
        return identity;
    }

    /**
     * The IAM OIDC provider of an issuer, in the role's account, as the page's example names it
     * ({@code arn:aws:iam::444455556666:oidc-provider/<issuer url>}).
     */
    private static String oidcProvider(String issuer, String roleArn) {
        if (issuer == null || !AwsArnUtils.isArn(roleArn)) {
            return null;
        }
        if (AwsArnUtils.isArn(issuer)) {
            return issuer;
        }
        int schemeEnd = issuer.indexOf("://");
        AwsArnUtils.Arn role = AwsArnUtils.parse(roleArn);
        return AwsArnUtils.Arn.global(role.partition(), "iam", role.accountId(),
                "oidc-provider/" + (schemeEnd < 0 ? issuer : issuer.substring(schemeEnd + 3))).toString();
    }

    private static HttpServerRequest request(RoutingContext routingContext) {
        return routingContext == null ? null : routingContext.request();
    }

    private static String sourceIp(HttpServerRequest request) {
        return request == null || request.remoteAddress() == null ? null : request.remoteAddress().host();
    }

    private static String userAgent(HttpServerRequest request) {
        return request == null ? null : request.getHeader("User-Agent");
    }
}
