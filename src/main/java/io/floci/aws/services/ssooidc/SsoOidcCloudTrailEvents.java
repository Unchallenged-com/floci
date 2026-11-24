package io.floci.aws.services.ssooidc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AccountResolver;
import io.floci.aws.core.common.IamConditionContextResolver;
import io.floci.aws.core.common.RegionResolver;
import io.floci.aws.core.common.RequestSourceAddress;
import io.floci.aws.services.cloudtrail.CloudTrailService;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Records the IAM Identity Center OIDC calls CloudTrail records: "CreateToken (event source
 * {@code sso.amazonaws.com})" and "CreateTokenWithIAM (event source {@code sso-oauth.amazonaws.com})"
 * (https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-info-in-cloudtrail.html, CloudTrail events
 * of OIDC API operations). RegisterClient and StartDeviceAuthorization are not in that list, so they are not
 * recorded.
 *
 * <ul>
 *   <li>CreateToken is the call of the user the token is issued to: {@code "type": "IdentityCenterUser"}, the
 *   account, {@code onBehalfOf} with the Identity Store user ID and ARN, and {@code credentialId}, as the
 *   IAM Identity Center guide's CreateToken record shows
 *   (https://docs.aws.amazon.com/singlesignon/latest/userguide/understanding-sso-entries.html) and as AWS
 *   records it since July 14, 2025 ("IAM Identity Center CloudTrail events will also specify
 *   IdentityCenterUser as the identity type instead of Unknown", AWS Security Blog, Important changes to
 *   CloudTrail events for AWS IAM Identity Center, 2024-11-19, updated 2025-11-26). The record keeps
 *   {@code clientId}, {@code grantType} and {@code deviceCode}, writes {@code clientSecret} and the issued
 *   {@code accessToken}, {@code refreshToken} and {@code idToken} as {@code HIDDEN_DUE_TO_SECURITY_REASONS},
 *   keeps {@code tokenType} and {@code expiresIn}, is not read-only, and names the Identity Store in
 *   {@code resources} ({@code "type": "IdentityStoreId"}).</li>
 *   <li>CreateTokenWithIAM is signed, so it is its IAM caller's. A 2026 record of a successful call keeps
 *   {@code clientId}, {@code grantType} and {@code scope}, hides {@code assertion}, answers
 *   {@code accessToken} (hidden), {@code expiresIn}, {@code tokenType} and {@code issuedTokenType}, carries the
 *   user's {@code identitystore:UserId}, {@code identitystore:IdentityStoreArn} and
 *   {@code identitycenter:CredentialId} in {@code additionalEventData}, and names the application in
 *   {@code resources} ({@code "type": "AWS::SSO::Application"}); a 2026 record of a failed call keeps the
 *   request, hidden members hidden, under the error's exception name ({@code InvalidRequestException}) with no
 *   {@code errorMessage}. The guide's token exchange example hides {@code code}, {@code assertion} and
 *   {@code subjectToken} (https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-cloudtrail-use-cases.html).</li>
 *   <li>Every other member botocore's {@code sso-oidc} model marks sensitive ({@code refreshToken},
 *   {@code codeVerifier}) is hidden as well; {@code code} is hidden in both calls, as the guide hides it.</li>
 * </ul>
 *
 * <p>Who the user is, and the token's {@code credentialId}, is {@link IdentityCenterCallers}'.
 */
@Provider
@Priority(Priorities.USER + 100)
public class SsoOidcCloudTrailEvents implements ContainerRequestFilter, ContainerResponseFilter {

    private static final Logger LOG = Logger.getLogger(SsoOidcCloudTrailEvents.class);
    /** What CloudTrail writes in place of a secret member of IAM Identity Center's calls. */
    public static final String HIDDEN = "HIDDEN_DUE_TO_SECURITY_REASONS";
    private static final String CREATE_TOKEN_SOURCE = "sso.amazonaws.com";
    private static final String CREATE_TOKEN_WITH_IAM_SOURCE = "sso-oauth.amazonaws.com";
    private static final String CALL = SsoOidcCloudTrailEvents.class.getName() + ".call";
    private static final List<String> CREATE_TOKEN_REQUEST = List.of("clientId", "clientSecret", "grantType",
            "deviceCode", "code", "refreshToken", "scope", "redirectUri", "codeVerifier");
    private static final List<String> CREATE_TOKEN_WITH_IAM_REQUEST = List.of("clientId", "grantType", "code",
            "refreshToken", "assertion", "scope", "redirectUri", "subjectToken", "subjectTokenType",
            "requestedTokenType", "codeVerifier");
    private static final Set<String> HIDDEN_REQUEST = Set.of("clientSecret", "code", "refreshToken", "assertion",
            "subjectToken", "codeVerifier");
    private static final List<String> CREATE_TOKEN_RESPONSE = List.of("accessToken", "tokenType", "expiresIn",
            "refreshToken", "idToken");
    private static final List<String> CREATE_TOKEN_WITH_IAM_RESPONSE = List.of("accessToken", "tokenType",
            "expiresIn", "refreshToken", "issuedTokenType");
    private static final Set<String> HIDDEN_RESPONSE = Set.of("accessToken", "refreshToken", "idToken");

    private final CloudTrailService cloudTrail;
    private final IdentityCenterCallers callers;
    private final AccountResolver accounts;
    private final RegionResolver regions;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;
    private final ResourceInfo resourceInfo;

    @Inject
    public SsoOidcCloudTrailEvents(CloudTrailService cloudTrail, IdentityCenterCallers callers,
                                   AccountResolver accounts, RegionResolver regions,
                                   CurrentVertxRequest currentRequest, ObjectMapper mapper,
                                   @Context ResourceInfo resourceInfo) {
        this.cloudTrail = cloudTrail;
        this.callers = callers;
        this.accounts = accounts;
        this.regions = regions;
        this.currentRequest = currentRequest;
        this.mapper = mapper;
        this.resourceInfo = resourceInfo;
    }

    /** A token request a trail records, as its body carried it. */
    private record Call(boolean withIam, JsonNode body) {
    }

    /** Notes a token request and its body before the controller reads it. */
    @Override
    public void filter(ContainerRequestContext request) {
        if (resourceInfo == null || resourceInfo.getResourceClass() != SsoOidcController.class
                || resourceInfo.getResourceMethod() == null
                || !"createToken".equals(resourceInfo.getResourceMethod().getName())) {
            return;
        }
        try {
            boolean withIam = "t".equals(request.getUriInfo().getQueryParameters().getFirst("aws_iam"));
            request.setProperty(CALL, new Call(withIam, json(IamConditionContextResolver.bufferEntity(request))));
        } catch (RuntimeException e) {
            // The call is served either way; a record that could not be prepared is logged, not raised.
            LOG.warnv(e, "Failed to read the OIDC token request for CloudTrail");
        }
    }

    /** Records the token request {@link #filter(ContainerRequestContext)} noted, as {@code response} answered it. */
    @Override
    public void filter(ContainerRequestContext request, ContainerResponseContext response) {
        if (!(request.getProperty(CALL) instanceof Call call)) {
            return;
        }
        try {
            JsonNode answer = response.getEntity() instanceof JsonNode node ? node : null;
            boolean failed = response.getStatus() >= 400;
            if (call.withIam()) {
                recordCreateTokenWithIam(request, response, call.body(), failed ? null : answer);
            } else if (!failed && answer != null) {
                recordCreateToken(call.body(), answer);
            }
        } catch (RuntimeException e) {
            // The call is answered either way; a record that could not be written is logged, not raised.
            LOG.warnv(e, "Failed to record the OIDC token request in CloudTrail");
        }
    }

    private void recordCreateToken(JsonNode body, JsonNode answer) {
        String accessToken = answer.path("accessToken").asText(null);
        ObjectNode identity = callers.userIdentity(accessToken);
        if (identity == null) {
            return;
        }
        ArrayNode resources = mapper.createArrayNode();
        resources.addObject()
                .put("accountId", regions.getAccountId())
                .put("type", "IdentityStoreId")
                .put("ARN", callers.identityStoreId());
        RoutingContext context = currentRequest.getCurrent();
        cloudTrail.emitManagementEvent(new CloudTrailService.ManagementEventInput(CREATE_TOKEN_SOURCE,
                "CreateToken", null, null, members(body, CREATE_TOKEN_REQUEST, HIDDEN_REQUEST),
                members(answer, CREATE_TOKEN_RESPONSE, HIDDEN_RESPONSE), false, sourceIp(context),
                userAgent(context), null, null, null, false, identity, null, resources));
    }

    private void recordCreateTokenWithIam(ContainerRequestContext request, ContainerResponseContext response,
                                          JsonNode body, JsonNode answer) {
        String authorization = request.getHeaderString(HttpHeaders.AUTHORIZATION);
        String accessKeyId = accounts.extractAccessKeyId(authorization);
        if (accessKeyId == null) {
            // An unsigned request is refused before it reaches IAM Identity Center's API.
            return;
        }
        String errorCode = answer == null ? errorCode(response) : null;
        ObjectNode result = null;
        ObjectNode additional = null;
        ArrayNode resources = null;
        if (answer != null) {
            result = members(answer, CREATE_TOKEN_WITH_IAM_RESPONSE, HIDDEN_RESPONSE);
            String accessToken = answer.path("accessToken").asText(null);
            additional = callers.tokenUser(accessToken);
            String applicationArn = body == null ? null : body.path("clientId").asText(null);
            if (applicationArn != null) {
                resources = mapper.createArrayNode();
                resources.addObject().put("type", "AWS::SSO::Application").put("ARN", applicationArn);
            }
        }
        RoutingContext context = currentRequest.getCurrent();
        cloudTrail.emitManagementEvent(new CloudTrailService.ManagementEventInput(CREATE_TOKEN_WITH_IAM_SOURCE,
                "CreateTokenWithIAM", regions.resolveRegionFromAuth(authorization), accessKeyId,
                members(body, CREATE_TOKEN_WITH_IAM_REQUEST, HIDDEN_REQUEST), result, false, sourceIp(context),
                userAgent(context), null, errorCode, null, false, null, additional, resources));
    }

    /**
     * The members of {@code source} named in {@code names}, in the order they came, with {@code hidden} ones
     * written {@link #HIDDEN}; null when it carries none.
     */
    private ObjectNode members(JsonNode source, List<String> names, Set<String> hidden) {
        if (source == null || !source.isObject()) {
            return null;
        }
        ObjectNode members = mapper.createObjectNode();
        for (Map.Entry<String, JsonNode> member : source.properties()) {
            if (!names.contains(member.getKey()) || member.getValue().isNull()) {
                continue;
            }
            if (hidden.contains(member.getKey())) {
                members.put(member.getKey(), HIDDEN);
            } else {
                members.set(member.getKey(), member.getValue().deepCopy());
            }
        }
        return members.isEmpty() ? null : members;
    }

    /** The exception name an OIDC error answers with, which the SDKs read the error from. */
    private static String errorCode(ContainerResponseContext response) {
        String type = response.getHeaderString("x-amzn-ErrorType");
        return type == null || type.isBlank() ? "InternalServerException" : type;
    }

    private JsonNode json(byte[] body) {
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            return mapper.readTree(body);
        } catch (IOException e) {
            // A body that is not JSON carries no member the record reads.
            return null;
        }
    }

    private static String sourceIp(RoutingContext context) {
        HttpServerRequest request = context == null ? null : context.request();
        return request == null ? null : RequestSourceAddress.of(request);
    }

    private static String userAgent(RoutingContext context) {
        HttpServerRequest request = context == null ? null : context.request();
        return request == null ? null : request.getHeader("User-Agent");
    }
}
