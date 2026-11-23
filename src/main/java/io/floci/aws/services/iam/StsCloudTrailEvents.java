package io.floci.aws.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AccountResolver;
import io.floci.aws.core.common.AwsArnUtils;
import io.floci.aws.core.common.AwsPartition;
import io.floci.aws.core.common.AwsPartitions;
import io.floci.aws.core.common.RequestContext;
import io.floci.aws.core.common.RequestSourceAddress;
import io.floci.aws.core.common.ServicePrincipals;
import io.floci.aws.core.common.XmlParser;
import io.floci.aws.services.cloudtrail.CloudTrailService;
import io.floci.aws.services.cloudtrail.CloudTrailShapes;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Records STS API calls as CloudTrail management events, as the IAM User Guide says CloudTrail
 * does: "CloudTrail logs all authenticated API requests to IAM and AWS STS API operations"
 * (https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html). The record follows
 * that page's STS events: {@code eventSource} {@code sts.amazonaws.com}, {@code requestParameters}
 * the request's members and {@code responseElements} the call's result, as botocore's STS model names,
 * types and redacts them ({@link CloudTrailShapes}), and {@code resources} the role a role is assumed
 * from.
 *
 * <p>STS has a global endpoint and Regional ones, and the two are recorded apart: "AWS CloudTrail logs
 * for requests made to the AWS STS global endpoint will be sent to the US East (N. Virginia) Region.
 * CloudTrail logs for requests served by AWS STS Regional endpoints will continue to be logged to their
 * respective Region in CloudTrail" (the same page), and "When you use an AWS STS Region-specific
 * endpoint, the trail in that Region delivers only the AWS STS events that occur in that Region"
 * (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html). A request
 * to the partition's global endpoint is recorded in its signing Region as a global service event,
 * which only a trail including global service events records; any other is recorded in the Region
 * it was signed for.
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
 * request". Every call is recorded, a trail or not, since event history keeps every management event.
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
     * The MFA code, which the model does not mark sensitive: the page's examples carry
     * {@code serialNumber} without the {@code tokenCode} that comes with it. The SAML assertion, the
     * web identity token and a trade-in token are left out as the model marks them sensitive.
     */
    private static final String MFA_CODE = "tokenCode";

    /**
     * Calls not recorded yet when STS answers them: how AWS records a token
     * {@code GetWebIdentityToken} issues, and anything about {@code GetDelegatedAccessToken}, is not
     * settled. A refused {@code GetWebIdentityToken} is recorded.
     */
    private static final Set<String> NOT_RECORDED_WHEN_ANSWERED =
            Set.of("GetWebIdentityToken", "GetDelegatedAccessToken");

    private static final int EXTENDED_ID_LENGTH = 8;
    private static final String ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

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

    /**
     * Records the call {@code response} answered, whether or not a trail selects it, as event history
     * keeps every management event; a record that cannot be built is logged, not raised.
     */
    public void record(String action, MultivaluedMap<String, String> params, String authorization,
                       Response response) {
        if (action == null || response == null || !(response.getEntity() instanceof String xml)) {
            return;
        }
        try {
            emit(action, params, authorization, IamCloudTrailEvents.Answer.of(xml, response.getStatus() >= 400),
                    xml);
        } catch (RuntimeException e) {
            LOG.warnv(e, "Failed to record STS call {0} in CloudTrail", action);
        }
    }

    private void emit(String action, MultivaluedMap<String, String> params, String authorization,
                      IamCloudTrailEvents.Answer answer, String xml) {
        String errorCode = answer.errorCode();
        if ("UnsupportedOperation".equals(errorCode)) {
            return;
        }
        if (errorCode == null ? NOT_RECORDED_WHEN_ANSWERED.contains(action) : "GetDelegatedAccessToken".equals(action)) {
            return;
        }
        ObjectNode result = errorCode == null && recordsResult(action) ? result(action, xml) : null;
        ObjectNode federatedCaller = null;
        if (isFederated(action)) {
            federatedCaller = result == null ? null : federatedCaller(action, params, result);
            if (federatedCaller == null) {
                return;
            }
        }
        ObjectNode requestParameters = requestParameters(action, params, errorCode);
        if ("AssumeRoleWithSAML".equals(action) && result != null) {
            requestParameters = samlRequestParameters(requestParameters, params, result);
        }
        HttpServerRequest request = request(currentRequest.getCurrent());
        String region = requestContext.getRegion();
        cloudTrail.emitManagementEvent(event(action, requestParameters,
                federatedCaller == null ? accounts.extractAccessKeyId(authorization) : null, federatedCaller,
                region, request, result, answer,
                errorCode == null ? additionalEventData(action, host(request), region, System.currentTimeMillis())
                        : null,
                errorCode == null ? resources(action, params) : null));
    }

    /**
     * {@code AssumeRoleWithSAML}'s parameters as the guide's example records them: the assertion's
     * {@code sAMLAssertionID} rather than the assertion, and the session's {@code roleSessionName},
     * which the assertion rather than the request names.
     */
    static ObjectNode samlRequestParameters(ObjectNode read, MultivaluedMap<String, String> params,
                                            ObjectNode result) {
        ObjectNode parameters = read == null ? MAPPER.createObjectNode() : read;
        String assertionId = params == null || params.getFirst("SAMLAssertion") == null ? null
                : SAMLAssertionVerifier.assertionId(params.getFirst("SAMLAssertion"));
        if (assertionId != null) {
            parameters.put("sAMLAssertionID", assertionId);
        }
        String arn = result.path("assumedRoleUser").path("arn").asText("");
        if (arn.contains("/")) {
            parameters.put("roleSessionName", arn.substring(arn.lastIndexOf('/') + 1));
        }
        return parameters.isEmpty() ? null : parameters;
    }

    /**
     * What a successful call's record adds: the {@code ExtendedRequestId} below, {@code RequestDetails}, the
     * endpoint type that served it and the Region serving it, which the guide's examples carry for the global
     * and the Regional endpoint alike, and for {@code AssumeRoleWithWebIdentity} how the provider's connection
     * was verified, "either IAMTrustStore or Thumbprint".
     */
    static ObjectNode additionalEventData(String action, String host, String region, long nowMillis) {
        ObjectNode data = MAPPER.createObjectNode();
        if ("AssumeRoleWithWebIdentity".equals(action)) {
            data.put("identityProviderConnectionVerificationMethod", "IAMTrustStore");
        }
        boolean global = globalEndpoint(host, region).isPresent();
        data.put("ExtendedRequestId", extendedRequestId(region, nowMillis, global));
        ObjectNode details = data.putObject("RequestDetails");
        details.put("endpointType", global ? "global" : "regional");
        if (region != null) {
            details.put("awsServingRegion", region);
        }
        return data;
    }

    /**
     * The {@code ExtendedRequestId} current CloudTrail records carry on a successful STS call, which
     * AWS does not document: the base64 of {@code 1:<Region>:S:<epoch milliseconds>:<R or G>:<id>},
     * {@code R} for a Regional endpoint and {@code G} for the global one, the id eight letters or
     * digits.
     */
    static String extendedRequestId(String region, long nowMillis, boolean global) {
        StringBuilder id = new StringBuilder(EXTENDED_ID_LENGTH);
        for (int i = 0; i < EXTENDED_ID_LENGTH; i++) {
            id.append(ALPHANUMERIC.charAt(ThreadLocalRandom.current().nextInt(ALPHANUMERIC.length())));
        }
        String plain = "1:" + region + ":S:" + nowMillis + ":" + (global ? "G" : "R") + ":" + id;
        return Base64.getEncoder().encodeToString(plain.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * The record of a call IAM enforcement refused with {@code refusal} before STS ran it, named after the
     * request's {@code Action}, with {@code "requestParameters": null} as AWS records an authorization
     * refusal and the code, message and request ID the refusal answered with; null for a request that
     * names none.
     */
    public static CloudTrailService.ManagementEventInput denied(MultivaluedMap<String, String> params,
                                                                String accessKeyId, String region,
                                                                RoutingContext routingContext, Response refusal) {
        String action = params.getFirst("Action");
        if (action == null || action.isBlank()) {
            return null;
        }
        return event(action, null, accessKeyId, null, region, request(routingContext), null,
                IamCloudTrailEvents.Answer.of(refusal.getEntity() instanceof String xml ? xml : "", true), null,
                null);
    }

    private static CloudTrailService.ManagementEventInput event(String action, ObjectNode requestParameters,
                                                                String accessKeyId, ObjectNode caller,
                                                                String region, HttpServerRequest request,
                                                                ObjectNode result,
                                                                IamCloudTrailEvents.Answer answer,
                                                                ObjectNode additionalEventData,
                                                                ArrayNode resources) {
        Optional<AwsPartition.GlobalEndpoint> global = globalEndpoint(host(request), region);
        return new CloudTrailService.ManagementEventInput(EVENT_SOURCE, action,
                global.map(AwsPartition.GlobalEndpoint::signingRegion).orElse(region), accessKeyId,
                requestParameters, result, isReadOnly(action),
                request == null ? null : RequestSourceAddress.of(request),
                request == null ? null : request.getHeader("User-Agent"), answer.requestId(), answer.errorCode(),
                answer.errorMessage(), global.isPresent(), caller, additionalEventData, resources);
    }

    /**
     * The partition's global STS endpoint when the request was sent to it, as its {@code Host} names it;
     * empty for a Regional endpoint.
     */
    static Optional<AwsPartition.GlobalEndpoint> globalEndpoint(String host, String region) {
        if (host == null || region == null) {
            return Optional.empty();
        }
        String name = host.split(":", 2)[0];
        return AwsPartitions.forRegionOrCommercial(region).globalEndpoint("sts")
                .filter(endpoint -> endpoint.hostname().equalsIgnoreCase(name));
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
     * The call's result as the record carries it, without its sensitive members, a credential's
     * expiration written as {@link CloudTrailShapes} writes an STS record's timestamps; null when it
     * carries nothing.
     */
    static ObjectNode result(String action, String xml) {
        return CloudTrailShapes.of("sts").result(action, xml);
    }

    /**
     * The request's members, without the sensitive ones and the MFA code; null for a call STS refused
     * as not authorized, as AWS records an authorization refusal.
     */
    static ObjectNode requestParameters(String action, MultivaluedMap<String, String> params, String errorCode) {
        if ("AccessDenied".equals(errorCode) || params == null) {
            return null;
        }
        ObjectNode read = CloudTrailShapes.of("sts").requestParameters(action, params);
        if (read == null) {
            return null;
        }
        read.remove(MFA_CODE);
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

    private static String host(HttpServerRequest request) {
        return request == null ? null : request.getHeader("Host");
    }

    private static HttpServerRequest request(RoutingContext routingContext) {
        return routingContext == null ? null : routingContext.request();
    }
}
