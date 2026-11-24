package io.floci.aws.services.ssoportal;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.RequestSourceAddress;
import io.floci.aws.services.cloudtrail.CloudTrailService;
import io.floci.aws.services.ssooidc.IdentityCenterCallers;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;

import java.util.Map;

/**
 * Records the AWS access portal calls CloudTrail records with the {@code sso.amazonaws.com} event source
 * (https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-info-in-cloudtrail.html, CloudTrail events of
 * AWS access portal API operations): ListAccounts, ListAccountRoles and GetRoleCredentials.
 *
 * <p>Each is the call of the user the bearer token was issued to: {@code "type": "IdentityCenterUser"}, the
 * account, {@code onBehalfOf} with the Identity Store user ID and ARN, and the {@code credentialId} of the
 * token, "the ID of the access token" for "AWS access portal events invoked with OIDC"
 * (https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-cloudtrail-use-cases.html), which
 * {@link IdentityCenterCallers} builds. 2026 records of the three calls are
 * {@code "eventType": "AwsServiceEvent"} and read-only, with {@code "requestParameters": null} and
 * {@code "responseElements": null}, so neither the token nor the role credentials are recorded; ListAccountRoles
 * carries the account in {@code "serviceEventDetails": {"account_id": ...}} and GetRoleCredentials the role and
 * account in {@code {"role_name": ..., "account_id": ...}}.
 */
@Provider
@Priority(Priorities.USER + 100)
public class SsoPortalCloudTrailEvents implements ContainerResponseFilter {

    private static final Logger LOG = Logger.getLogger(SsoPortalCloudTrailEvents.class);
    private static final String EVENT_SOURCE = "sso.amazonaws.com";
    private static final String BEARER_TOKEN = "x-amz-sso_bearer_token";
    /** The controller method that serves each recorded call, and the call's event name. */
    private static final Map<String, String> EVENT_NAMES = Map.of(
            "listAccounts", "ListAccounts",
            "listAccountRoles", "ListAccountRoles",
            "getRoleCredentials", "GetRoleCredentials");

    private final CloudTrailService cloudTrail;
    private final IdentityCenterCallers callers;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;
    private final ResourceInfo resourceInfo;

    @Inject
    public SsoPortalCloudTrailEvents(CloudTrailService cloudTrail, IdentityCenterCallers callers,
                                     CurrentVertxRequest currentRequest, ObjectMapper mapper,
                                     @Context ResourceInfo resourceInfo) {
        this.cloudTrail = cloudTrail;
        this.callers = callers;
        this.currentRequest = currentRequest;
        this.mapper = mapper;
        this.resourceInfo = resourceInfo;
    }

    /** Records a portal call the portal answered. */
    @Override
    public void filter(ContainerRequestContext request, ContainerResponseContext response) {
        if (resourceInfo == null || resourceInfo.getResourceClass() != SsoPortalController.class
                || resourceInfo.getResourceMethod() == null || response.getStatus() >= 400) {
            return;
        }
        String eventName = EVENT_NAMES.get(resourceInfo.getResourceMethod().getName());
        if (eventName == null) {
            return;
        }
        try {
            ObjectNode identity = callers.userIdentity(request.getHeaderString(BEARER_TOKEN));
            if (identity == null) {
                return;
            }
            MultivaluedMap<String, String> query = request.getUriInfo().getQueryParameters();
            ObjectNode details = null;
            if ("ListAccountRoles".equals(eventName)) {
                details = mapper.createObjectNode().put("account_id", query.getFirst("account_id"));
            } else if ("GetRoleCredentials".equals(eventName)) {
                details = mapper.createObjectNode().put("role_name", query.getFirst("role_name"))
                        .put("account_id", query.getFirst("account_id"));
            }
            RoutingContext context = currentRequest.getCurrent();
            cloudTrail.emitServiceEvent(new CloudTrailService.ManagementEventInput(EVENT_SOURCE, eventName, null,
                    null, null, null, true, sourceIp(context), userAgent(context), null, null, null, false,
                    identity, null, null), details);
        } catch (RuntimeException e) {
            // The call is answered either way; a record that could not be written is logged, not raised.
            LOG.warnv(e, "Failed to record CloudTrail call {0}", eventName);
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
