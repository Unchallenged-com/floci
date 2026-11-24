package io.floci.aws.services.organizations;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AwsErrorResponse;
import io.floci.aws.core.common.AwsPartition;
import io.floci.aws.core.common.AwsPartitions;
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
import java.util.Optional;

/**
 * Records Organizations' calls as CloudTrail management events: "All AWS Organizations actions are logged by
 * CloudTrail" (https://docs.aws.amazon.com/organizations/latest/userguide/orgs_cloudtrail-integration.html).
 * Which calls, and which are read-only, is the vendored {@code aws/organizations-cloudtrail-events.json}
 * ({@link CloudTrailEventCatalog}): the calls Floci serves, read-only as AWS's Service Reference gives their
 * access level, as records of DescribeOrganization, ListAccounts and LeaveOrganization (2024) show them.
 *
 * <p>The record follows that page's examples and those records:
 * <ul>
 *   <li>{@code eventSource} {@code organizations.amazonaws.com}, recorded in the Region Organizations' endpoint
 *   signs for in the caller's partition ({@code us-east-1} in {@code aws}), as a global service's event,
 *   whatever Region the caller named: "You can view all CloudTrail information for AWS Organizations only in
 *   the US East (N. Virginia) Region";</li>
 *   <li>{@code requestParameters} are the request's members with a lower first letter ({@code "accountId"},
 *   {@code "parentId"}, {@code "target": {"type", "id"}}), and {@code responseElements} the answer in the same
 *   form ({@code "organizationalUnit"}, {@code "createAccountStatus"}), null for a read-only call and for a call
 *   that answers nothing ({@code CloseAccount});</li>
 *   <li>a member botocore's model marks sensitive is written {@code "****"}, as the CreateAccount example writes
 *   {@code email} and {@code accountName};</li>
 *   <li>a timestamp in an answer is written {@code "Jul 17, 2025, 2:53:40 PM"}, as the page's 2025
 *   EffectivePolicyValidation example writes its timestamps;</li>
 *   <li>a failed call keeps its members and is recorded under its error's type, with its message and
 *   {@code "responseElements": null}, as the AttachPolicy example ({@code PolicyTypeNotEnabledException});</li>
 *   <li>a call IAM enforcement refuses is recorded as {@code AccessDenied} with {@code "requestParameters": null},
 *   as the 2024 records of refused DescribeOrganization, ListAccounts and LeaveOrganization calls show.</li>
 * </ul>
 * Every call is recorded in the account that made it ("CloudTrail will log events in the account that takes a
 * given action"), a trail or not, since event history keeps every management event. The service events
 * Organizations logs on its own ({@code CreateAccountResult}, {@code CloseAccountResult}) are not recorded.
 */
@ApplicationScoped
public class OrganizationsCloudTrailEvents implements ManagementEventSource {

    private static final Logger LOG = Logger.getLogger(OrganizationsCloudTrailEvents.class);
    private static final String SERVICE = "organizations";
    private static final String EVENT_SOURCE = ServicePrincipals.of(SERVICE);
    private static final CloudTrailShapes.JsonStyle STYLE = new CloudTrailShapes.JsonStyle(false,
            DateTimeFormatter.ofPattern("MMM d, yyyy, h:mm:ss a", Locale.US).withZone(ZoneOffset.UTC), "****");

    private final CloudTrailService cloudTrail;
    private final RequestContext requestContext;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;

    @Inject
    public OrganizationsCloudTrailEvents(CloudTrailService cloudTrail, RequestContext requestContext,
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
                    ? shapes.result(action, mapper.valueToTree(response.getEntity()), STYLE) : null;
            cloudTrail.emitManagementEvent(event(action, shapes.requestParameters(action, request, STYLE),
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
     * The record of a call IAM enforcement refused with {@code refusal} before Organizations ran it, with
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
        // Recorded in the Region Organizations' endpoint signs for in the request's partition, as a global
        // service's event, which only a trail including global service events records.
        Optional<AwsPartition.GlobalEndpoint> global = AwsPartitions.forRegionOrCommercial(region)
                .globalEndpoint(SERVICE);
        CloudTrailEventCatalog catalog = CloudTrailEventCatalog.of(SERVICE);
        return new CloudTrailService.ManagementEventInput(EVENT_SOURCE, catalog.eventName(action),
                global.map(AwsPartition.GlobalEndpoint::signingRegion).orElse(region), accessKeyId,
                requestParameters, result, catalog.isReadOnly(action), sourceIp, userAgent, null, errorCode,
                errorMessage, global.isPresent(), null, null, null);
    }

    private static HttpServerRequest request(RoutingContext routingContext) {
        return routingContext == null ? null : routingContext.request();
    }
}
