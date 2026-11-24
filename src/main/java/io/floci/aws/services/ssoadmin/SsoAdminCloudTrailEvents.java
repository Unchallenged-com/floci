package io.floci.aws.services.ssoadmin;

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
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

/**
 * Records the public IAM Identity Center operations as CloudTrail management events: "The following list
 * contains the CloudTrail events that the public IAM Identity Center operations emit with the
 * sso.amazonaws.com event source"
 * (https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-info-in-cloudtrail.html). Which calls, and
 * which are read-only, is the vendored {@code aws/sso-cloudtrail-events.json} ({@link CloudTrailEventCatalog}):
 * the guide's list, read-only as AWS's Service Reference gives their access level. The calls Floci serves that
 * the list does not name ({@code AddRegion}, {@code PutApplicationSessionConfiguration}, ...) are not recorded.
 *
 * <p>The record follows a 2025 record of CreateAccountAssignment:
 * <ul>
 *   <li>{@code eventSource} {@code sso.amazonaws.com}, recorded in the Region the call was signed for, as the
 *   caller who signed it;</li>
 *   <li>{@code requestParameters} are the request's members with a lower first letter ({@code instanceArn},
 *   {@code targetId}, {@code permissionSetArn}), and {@code responseElements} the answer in the same form
 *   ({@code accountAssignmentCreationStatus}), null for a read-only call and for a call that answers nothing, as
 *   CloudTrail's record contents give {@code responseElements} "For readOnly APIs, this field is null"
 *   (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
 *   and the guide's DescribePermissionsPolicies example records it;</li>
 *   <li>a timestamp in an answer is written {@code "May 24, 2025, 2:51:14 PM"}, with a narrow no-break space
 *   before the period of day, as 2025 records of IAM Identity Center's directory write theirs;</li>
 *   <li>a document member ({@code actorPolicy}) is written as the call carried it.</li>
 * </ul>
 * A failed call keeps its members and is recorded under its error's type, with its message and
 * {@code "responseElements": null}; a call IAM enforcement refuses is recorded as {@link #REFUSED} with
 * {@code "requestParameters": null}. Every call is recorded, a trail or not, since event history keeps every
 * management event.
 */
@ApplicationScoped
public class SsoAdminCloudTrailEvents implements ManagementEventSource {

    private static final Logger LOG = Logger.getLogger(SsoAdminCloudTrailEvents.class);
    /** The credential scope SSO Admin is signed for, and the name of its event table. */
    private static final String SERVICE = "sso";
    /** The botocore model its members are read with. */
    private static final String SHAPES = "sso-admin";
    private static final String EVENT_SOURCE = ServicePrincipals.of(SERVICE);
    private static final CloudTrailShapes.JsonStyle STYLE = new CloudTrailShapes.JsonStyle(false,
            DateTimeFormatter.ofPattern("MMM d, yyyy, h:mm:ss a", Locale.US).withZone(ZoneOffset.UTC));

    private final CloudTrailService cloudTrail;
    private final RequestContext requestContext;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;

    @Inject
    public SsoAdminCloudTrailEvents(CloudTrailService cloudTrail, RequestContext requestContext,
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
            CloudTrailShapes shapes = CloudTrailShapes.of(SHAPES);
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
     * The record of a call IAM enforcement refused with {@code refusal} before IAM Identity Center ran it, with
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
