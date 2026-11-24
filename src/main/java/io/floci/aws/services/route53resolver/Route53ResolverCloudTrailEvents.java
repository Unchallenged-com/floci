package io.floci.aws.services.route53resolver;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AwsErrorResponse;
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

/**
 * Records Route 53 Resolver's calls as CloudTrail management events: "All Route 53 actions are logged by
 * CloudTrail" (https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/logging-using-cloudtrail.html), Resolver's
 * among them. Which calls, and which are read-only, is the vendored {@code aws/route53resolver-cloudtrail-events.json}
 * ({@link CloudTrailEventCatalog}): the calls Floci serves, read-only as AWS's Service Reference gives their access
 * level.
 *
 * <p>The record follows that page's {@code CreateResolverEndpoint} example and the 2024 records of
 * {@code DeleteResolverQueryLogConfig}:
 * <ul>
 *   <li>under the call's own name, from {@code route53resolver.amazonaws.com}, in the Region the call was made
 *   in, Resolver being a Regional service, and with no {@code apiVersion};</li>
 *   <li>{@code requestParameters} are the request's members with a lower first letter ({@code "creatorRequestId"},
 *   {@code "ipAddresses": [{"subnetId"}]}, {@code "tags": []}), and {@code responseElements} the answer in the
 *   same form ({@code "resolverEndpoint"}, its {@code "creationTime"} as answered), typed as botocore's model
 *   types them; {@code responseElements} is null for a read-only call;</li>
 *   <li>a call that fails keeps its members and is recorded under its error's type, with its message;</li>
 *   <li>a call IAM enforcement refuses is recorded as {@code AccessDenied} with {@code "requestParameters": null}
 *   and the refusal's message, as Route 53's refused calls are.</li>
 * </ul>
 * Every call is recorded, a trail or not, since event history keeps every management event.
 */
@ApplicationScoped
public class Route53ResolverCloudTrailEvents implements ManagementEventSource {

    private static final Logger LOG = Logger.getLogger(Route53ResolverCloudTrailEvents.class);
    private static final String SERVICE = "route53resolver";
    private static final String EVENT_SOURCE = ServicePrincipals.of(SERVICE);

    private final CloudTrailService cloudTrail;
    private final RequestContext requestContext;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;

    @Inject
    public Route53ResolverCloudTrailEvents(CloudTrailService cloudTrail, RequestContext requestContext,
                                           CurrentVertxRequest currentRequest, ObjectMapper mapper) {
        this.cloudTrail = cloudTrail;
        this.requestContext = requestContext;
        this.currentRequest = currentRequest;
        this.mapper = mapper;
    }

    /** Records the call {@code response} answered, a failed one included, as the caller the request was signed by. */
    void record(String action, JsonNode request, String region, Response response) {
        CloudTrailEventCatalog catalog = CloudTrailEventCatalog.of(SERVICE);
        if (!catalog.isManagementEvent(action) || response == null) {
            return;
        }
        try {
            CloudTrailShapes shapes = CloudTrailShapes.of(SERVICE);
            String errorCode = null;
            String errorMessage = null;
            if (response.getStatus() >= 400) {
                if (!(response.getEntity() instanceof AwsErrorResponse error)) {
                    // A failure that names no error has no errorCode to be recorded under.
                    return;
                }
                errorCode = error.type();
                errorMessage = error.message();
            }
            ObjectNode result = errorCode == null && !catalog.isReadOnly(action) && response.getEntity() != null
                    ? shapes.result(action, mapper.valueToTree(response.getEntity())) : null;
            cloudTrail.emitManagementEvent(event(action, shapes.requestParameters(action, request),
                    requestContext.getAccessKeyId(), region, request(currentRequest.getCurrent()), result, errorCode,
                    errorMessage));
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
     * The record of a call IAM enforcement refused with {@code refusal} before Resolver ran it, with
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
        CloudTrailEventCatalog catalog = CloudTrailEventCatalog.of(SERVICE);
        return new CloudTrailService.ManagementEventInput(EVENT_SOURCE, catalog.eventName(action), region,
                accessKeyId, requestParameters, result, catalog.isReadOnly(action),
                request == null ? null : RequestSourceAddress.of(request),
                request == null ? null : request.getHeader("User-Agent"), null, errorCode, errorMessage);
    }

    private static HttpServerRequest request(RoutingContext routingContext) {
        return routingContext == null ? null : routingContext.request();
    }
}
