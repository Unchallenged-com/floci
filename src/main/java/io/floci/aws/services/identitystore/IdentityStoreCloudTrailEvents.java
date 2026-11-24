package io.floci.aws.services.identitystore;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AwsException;
import io.floci.aws.core.common.RequestContext;
import io.floci.aws.core.common.RequestSourceAddress;
import io.floci.aws.core.common.ServicePrincipals;
import io.floci.aws.services.cloudtrail.CloudTrailEventCatalog;
import io.floci.aws.services.cloudtrail.CloudTrailService;
import io.floci.aws.services.cloudtrail.CloudTrailShapes;
import io.floci.aws.services.cloudtrail.ManagementEventSource;
import io.floci.aws.services.ssooidc.SsoOidcCloudTrailEvents;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;

/**
 * Records the public Identity Store operations as CloudTrail management events: "The following list contains
 * the CloudTrail events that the public Identity Store operations emit with the identitystore.amazonaws.com
 * event source" (https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-info-in-cloudtrail.html). Which
 * calls, and which are read-only, is the vendored {@code aws/identitystore-cloudtrail-events.json}
 * ({@link CloudTrailEventCatalog}): the guide's list, read-only as AWS's Service Reference gives their access
 * level. The console's {@code sso-directory.amazonaws.com} events have no public API, so Floci makes none.
 *
 * <p>The record is the caller's who signed it, in the Region it was signed for, under {@code eventSource}
 * {@code identitystore.amazonaws.com}, with {@code requestParameters} the request's members with a lower first
 * letter ({@code identityStoreId}, {@code groupId}, {@code memberId}) and {@code responseElements} the answer in
 * the same form, null for a read-only call and for a call that answers nothing.
 *
 * <p>A member botocore's model marks sensitive (the user name and attributes, a group's display name and
 * description, an external ID), and every attribute value, is written {@code HIDDEN_DUE_TO_SECURITY_REASONS}:
 * IAM Identity Center "will replace the displayName value in the administrative CloudTrail events for
 * CreateGroup and UpdateGroup with a fixed text value of HIDDEN_DUE_TO_SECURITY_REASONS" since July 14, 2025
 * (AWS Security Blog, Important changes to CloudTrail events for AWS IAM Identity Center, 2024-11-19, updated
 * 2025-11-26), and the guide's SCIM CreateUser event writes userName, displayName, givenName and familyName so
 * (https://docs.aws.amazon.com/singlesignon/latest/userguide/scim-logging-using-cloudtrail.html).
 *
 * <p>A failed call keeps its members and is recorded under its error's type, with its message and
 * {@code "responseElements": null}; a call IAM enforcement refuses is recorded as {@link #REFUSED} with
 * {@code "requestParameters": null}. Every call is recorded, a trail or not, since event history keeps every
 * management event.
 */
@ApplicationScoped
public class IdentityStoreCloudTrailEvents implements ManagementEventSource {

    private static final Logger LOG = Logger.getLogger(IdentityStoreCloudTrailEvents.class);
    private static final String SERVICE = "identitystore";
    private static final String EVENT_SOURCE = ServicePrincipals.of(SERVICE);
    private static final CloudTrailShapes.JsonStyle STYLE = new CloudTrailShapes.JsonStyle(false, null,
            SsoOidcCloudTrailEvents.HIDDEN);

    private final CloudTrailService cloudTrail;
    private final RequestContext requestContext;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;

    @Inject
    public IdentityStoreCloudTrailEvents(CloudTrailService cloudTrail, RequestContext requestContext,
                                         CurrentVertxRequest currentRequest, ObjectMapper mapper) {
        this.cloudTrail = cloudTrail;
        this.requestContext = requestContext;
        this.currentRequest = currentRequest;
        this.mapper = mapper;
    }

    /**
     * Records the call {@code response} answered, or that failed with {@code error} when it is set, as the
     * caller the request was signed by.
     */
    void record(String action, JsonNode request, String region, Response response, AwsException error) {
        CloudTrailEventCatalog catalog = CloudTrailEventCatalog.of(SERVICE);
        if (!catalog.isManagementEvent(action)) {
            return;
        }
        try {
            CloudTrailShapes shapes = CloudTrailShapes.of(SERVICE);
            boolean answered = error == null && response != null && response.getStatus() < 400;
            ObjectNode result = answered && !catalog.isReadOnly(action) && response.getEntity() != null
                    ? shapes.result(action, mapper.valueToTree(response.getEntity()), STYLE) : null;
            cloudTrail.emitManagementEvent(event(action, shapes.requestParameters(action, request, STYLE),
                    requestContext.getAccessKeyId(), region, request(currentRequest.getCurrent()), result,
                    error == null ? null : error.jsonType(), error == null ? null : error.getMessage()));
        } catch (RuntimeException e) {
            // The call is answered either way; a record that could not be written is logged, not raised.
            LOG.warnv(e, "Failed to record CloudTrail call {0}", action);
        }
    }

    @Override
    public String credentialScope() {
        return SERVICE;
    }

    /**
     * The record of a call IAM enforcement refused with {@code refusal} before the Identity Store ran it, with
     * {@code "requestParameters": null} and, as {@link #REFUSED}, the message the refusal answered with; null for
     * a call that is not a management event.
     */
    @Override
    public CloudTrailService.ManagementEventInput refused(String operation, String accessKeyId, String region,
                                                          RoutingContext routingContext, Response refusal) {
        if (!CloudTrailEventCatalog.of(SERVICE).isManagementEvent(operation)) {
            return null;
        }
        return event(operation, null, accessKeyId, region, request(routingContext), null, REFUSED,
                refusalMessage(refusal));
    }

    private static CloudTrailService.ManagementEventInput event(String action, ObjectNode requestParameters,
                                                                String accessKeyId, String region,
                                                                HttpServerRequest request, ObjectNode result,
                                                                String errorCode, String errorMessage) {
        String sourceIp = request == null ? null : RequestSourceAddress.of(request);
        String userAgent = request == null ? null : request.getHeader("User-Agent");
        CloudTrailEventCatalog catalog = CloudTrailEventCatalog.of(SERVICE);
        return new CloudTrailService.ManagementEventInput(EVENT_SOURCE, catalog.eventName(action), region,
                accessKeyId, requestParameters, result, catalog.isReadOnly(action), sourceIp, userAgent, null,
                errorCode, errorMessage);
    }

    private static HttpServerRequest request(RoutingContext routingContext) {
        return routingContext == null ? null : routingContext.request();
    }
}
