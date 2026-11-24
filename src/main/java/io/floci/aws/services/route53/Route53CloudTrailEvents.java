package io.floci.aws.services.route53;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AccountResolver;
import io.floci.aws.core.common.AwsPartition;
import io.floci.aws.core.common.AwsPartitions;
import io.floci.aws.core.common.IamConditionContextResolver;
import io.floci.aws.core.common.RegionResolver;
import io.floci.aws.core.common.RequestSourceAddress;
import io.floci.aws.core.common.ServicePrincipals;
import io.floci.aws.core.common.XmlParser;
import io.floci.aws.services.cloudtrail.CloudTrailEventCatalog;
import io.floci.aws.services.cloudtrail.CloudTrailService;
import io.floci.aws.services.cloudtrail.CloudTrailShapes;
import io.floci.aws.services.cloudtrail.ManagementEventSource;
import io.floci.aws.services.iam.IamActionRegistry;
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
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;

/**
 * Records Route 53's calls as CloudTrail management events: "All Route 53 actions are logged by CloudTrail"
 * (https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/logging-using-cloudtrail.html). Which calls, and
 * which are read-only, is the vendored {@code aws/route53-cloudtrail-events.json} ({@link CloudTrailEventCatalog}):
 * the calls Floci serves, read-only as AWS's Service Reference gives their access level.
 *
 * <p>Route 53's API is REST-XML, so a call is told by its route. Its record follows that page's examples and the
 * records of {@code ChangeResourceRecordSets} (2025), {@code ListHostedZones} (2026) and a refused
 * {@code CreateHostedZone} (2024):
 * <ul>
 *   <li>under the call's own name, from {@code route53.amazonaws.com}, with {@code "apiVersion": "2013-04-01"},
 *   recorded in the Region Route 53's endpoint signs for in the caller's partition ({@code us-east-1} in
 *   {@code aws}), as a global service's event, whatever Region the caller named: "To view events for Route 53
 *   API requests, you must choose US East (N. Virginia)";</li>
 *   <li>{@code requestParameters} are the members the call carries in its path, its query and its XML body,
 *   named after botocore's Route 53 model with a lower first letter ({@code "hostedZoneId"}, {@code "tTL"},
 *   {@code "iPAddress"}) and typed as it types them; null for a call that carries none
 *   ({@code ListHostedZones});</li>
 *   <li>{@code responseElements} is the answer in the same form, its {@code Location} header as
 *   {@code "location"} and its timestamps written {@code "May 1, 2025 11:46:14 AM"}; null for a read-only
 *   call;</li>
 *   <li>{@code ChangeResourceRecordSets} carries {@code "additionalEventData": {"Note": "Do not use to
 *   reconstruct hosted zone"}};</li>
 *   <li>a call that fails keeps its members and is recorded under the error's code, with its message;</li>
 *   <li>a call IAM enforcement refuses is recorded as {@code AccessDenied} with the refusal's message,
 *   {@code "requestParameters": null} and no {@code apiVersion}.</li>
 * </ul>
 * Every call is recorded, a trail or not, since event history keeps every management event.
 */
@Provider
@Priority(Priorities.USER - 100)
public class Route53CloudTrailEvents implements ContainerRequestFilter, ContainerResponseFilter,
        ManagementEventSource {

    private static final Logger LOG = Logger.getLogger(Route53CloudTrailEvents.class);
    private static final String SERVICE = "route53";
    private static final String EVENT_SOURCE = ServicePrincipals.of(SERVICE);
    /** The API version botocore's Route 53 model is, which every answered call's record names. */
    private static final String API_VERSION = "2013-04-01";
    /** The note the page's and the 2025 record's {@code ChangeResourceRecordSets} carry. */
    private static final String CHANGE_NOTE = "Do not use to reconstruct hosted zone";
    /** The routing context entry that holds the call a request makes until one record of it is written. */
    private static final String CALL = Route53CloudTrailEvents.class.getName() + ".call";

    private final CloudTrailService cloudTrail;
    private final AccountResolver accounts;
    private final RegionResolver regions;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;

    @Inject
    public Route53CloudTrailEvents(CloudTrailService cloudTrail, AccountResolver accounts, RegionResolver regions,
                                   CurrentVertxRequest currentRequest, ObjectMapper mapper) {
        this.cloudTrail = cloudTrail;
        this.accounts = accounts;
        this.regions = regions;
        this.currentRequest = currentRequest;
        this.mapper = mapper;
    }

    /** A Route 53 call a trail records, as its request carried it. */
    private record Call(String operation, Map<String, String> labels, MultivaluedMap<String, String> query,
                        XmlParser.XmlElement body) {
    }

    /** Notes the management call a request makes, with its members, before IAM enforcement and the controller. */
    @Override
    public void filter(ContainerRequestContext request) {
        if (!signedForRoute53(request.getHeaderString(HttpHeaders.AUTHORIZATION))) {
            return;
        }
        RoutingContext context = currentRequest.getCurrent();
        if (context == null) {
            return;
        }
        try {
            String operation = IamActionRegistry.routedOperation(SERVICE, request);
            if (!CloudTrailEventCatalog.of(SERVICE).isManagementEvent(operation)) {
                return;
            }
            byte[] body = IamConditionContextResolver.bufferEntity(request);
            context.put(CALL, new Call(operation, IamActionRegistry.pathLabels(SERVICE, request),
                    request.getUriInfo().getQueryParameters(), body == null || body.length == 0 ? null
                            : XmlParser.parseDocumentElementTree(new String(body, StandardCharsets.UTF_8))));
        } catch (RuntimeException e) {
            // The call is served either way; a record that could not be prepared is logged, not raised.
            LOG.warnv(e, "Failed to read the Route 53 call for CloudTrail");
        }
    }

    /** Records the call {@link #filter(ContainerRequestContext)} noted, as {@code response} answered it. */
    @Override
    public void filter(ContainerRequestContext request, ContainerResponseContext response) {
        RoutingContext context = currentRequest.getCurrent();
        if (context == null || !(context.remove(CALL) instanceof Call call)) {
            return;
        }
        try {
            CloudTrailEventCatalog catalog = CloudTrailEventCatalog.of(SERVICE);
            boolean readOnly = catalog.isReadOnly(call.operation());
            String xml = response.getEntity() instanceof String text ? text : null;
            String errorCode = null;
            String errorMessage = null;
            ObjectNode result = null;
            if (response.getStatus() >= 400) {
                errorCode = xml == null ? null : XmlParser.extractFirst(xml, "Code", null);
                if (errorCode == null) {
                    // A failure that names no error has no errorCode to be recorded under.
                    return;
                }
                errorMessage = XmlParser.extractFirst(xml, "Message", null);
            } else if (!readOnly) {
                result = CloudTrailShapes.of(SERVICE).restXmlResult(call.operation(), xml,
                        response::getHeaderString);
            }
            ObjectNode note = errorCode == null && "ChangeResourceRecordSets".equals(call.operation())
                    ? mapper.createObjectNode().put("Note", CHANGE_NOTE) : null;
            String authorization = request.getHeaderString(HttpHeaders.AUTHORIZATION);
            cloudTrail.emitManagementEvent(event(call.operation(), regions.resolveRegionFromAuth(authorization),
                    accounts.extractAccessKeyId(authorization), requestParameters(call), result, context, errorCode,
                    errorMessage, note, API_VERSION));
        } catch (RuntimeException e) {
            // The call is answered either way; a record that could not be written is logged, not raised.
            LOG.warnv(e, "Failed to record CloudTrail call {0}", call.operation());
        }
    }

    @Override
    public String credentialScope() {
        return SERVICE;
    }

    /**
     * The record of a call IAM enforcement refused with {@code refusal} before Route 53 ran it:
     * {@code AccessDenied} with the refusal's message, {@code "requestParameters": null} and no
     * {@code apiVersion}, as the 2024 record of a refused {@code CreateHostedZone} shows; null for a call that
     * is not a management event.
     */
    @Override
    public CloudTrailService.ManagementEventInput refused(String operation, String accessKeyId, String region,
                                                          RoutingContext routingContext, Response refusal) {
        if (routingContext != null) {
            // The refusal is this call's only record: the answer it gets is not recorded again.
            routingContext.remove(CALL);
        }
        if (!CloudTrailEventCatalog.of(SERVICE).isManagementEvent(operation)) {
            return null;
        }
        return event(operation, region, accessKeyId, null, null, routingContext, REFUSED, refusalMessage(refusal),
                null, null);
    }

    private static CloudTrailService.ManagementEventInput event(String operation, String region, String accessKeyId,
                                                                ObjectNode requestParameters, ObjectNode result,
                                                                RoutingContext context, String errorCode,
                                                                String errorMessage, ObjectNode additionalEventData,
                                                                String apiVersion) {
        HttpServerRequest request = context == null ? null : context.request();
        // Recorded in the Region Route 53's endpoint signs for in the request's partition, as a global service's
        // event, which only a trail including global service events records.
        Optional<AwsPartition.GlobalEndpoint> global = AwsPartitions.forRegionOrCommercial(region)
                .globalEndpoint(SERVICE);
        CloudTrailEventCatalog catalog = CloudTrailEventCatalog.of(SERVICE);
        return new CloudTrailService.ManagementEventInput(EVENT_SOURCE, catalog.eventName(operation),
                global.map(AwsPartition.GlobalEndpoint::signingRegion).orElse(region), accessKeyId,
                requestParameters, result, catalog.isReadOnly(operation),
                request == null ? null : RequestSourceAddress.of(request),
                request == null ? null : request.getHeader("User-Agent"), null, errorCode, errorMessage,
                global.isPresent(), null, additionalEventData, null, apiVersion);
    }

    private static ObjectNode requestParameters(Call call) {
        return CloudTrailShapes.of(SERVICE).requestParameters(call.operation(), call.labels(), call.query(),
                call.body());
    }

    /** Whether a request is signed for Route 53, whose routes no other service's requests take. */
    private static boolean signedForRoute53(String authorization) {
        return authorization != null && authorization.contains("/" + SERVICE + "/aws4_request");
    }
}
