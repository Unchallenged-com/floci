package io.floci.aws.services.guardduty;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AccountResolver;
import io.floci.aws.core.common.IamConditionContextResolver;
import io.floci.aws.core.common.RegionResolver;
import io.floci.aws.core.common.RequestSourceAddress;
import io.floci.aws.core.common.ServicePrincipals;
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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Records GuardDuty's calls as CloudTrail management events: "By default, CloudTrail logs all the GuardDuty
 * API operations provided in the Amazon GuardDuty API Reference as events in CloudTrail files"
 * (https://docs.aws.amazon.com/guardduty/latest/ug/logging-using-cloudtrail.html). Which calls, and which are
 * read-only, is the vendored {@code aws/guardduty-cloudtrail-events.json} ({@link CloudTrailEventCatalog}): the
 * calls Floci serves.
 *
 * <p>GuardDuty's API is REST-JSON, so a call is told by its route. Its record is written as the records of
 * {@code CreateDetector}, {@code DeleteDetector}, {@code GetDetector}, {@code ListDetectors},
 * {@code UpdateDetector}, {@code DeleteMembers} and {@code DeletePublishingDestination} since 2024 write it:
 * <ul>
 *   <li>under the call's own name, from {@code guardduty.amazonaws.com};</li>
 *   <li>{@code requestParameters} are the members the call carries in its path, its query and its body, named
 *   as its JSON names them ({@code "detectorId"}, {@code "findingPublishingFrequency"}, {@code "accountIds"})
 *   and typed as botocore's GuardDuty model types them, without the members the model marks sensitive; null
 *   for a call that carries none ({@code ListDetectors});</li>
 *   <li>{@code responseElements} is the answer in the same form ({@code CreateDetector}'s
 *   {@code "detectorId"}), null for a read-only call and for an answer that carries nothing
 *   ({@code DeleteDetector});</li>
 *   <li>a call IAM enforcement refuses keeps its members and is recorded as {@code AccessDenied} with no
 *   {@code errorMessage}: the refusal's message is written as {@code "responseElements": {"message": ...}}
 *   for a write, and not at all for a read-only call.</li>
 * </ul>
 * A call that fails otherwise is not recorded: no record shows how GuardDuty writes one.
 *
 * <p>The call is read before IAM enforcement runs, so the record of a refusal can carry its members.
 */
@Provider
@Priority(Priorities.USER - 100)
public class GuardDutyCloudTrailEvents implements ContainerRequestFilter, ContainerResponseFilter,
        ManagementEventSource {

    private static final Logger LOG = Logger.getLogger(GuardDutyCloudTrailEvents.class);
    private static final String SERVICE = "guardduty";
    private static final String EVENT_SOURCE = ServicePrincipals.of(SERVICE);
    /** The routing context entry that holds the call a request makes until one record of it is written. */
    private static final String CALL = GuardDutyCloudTrailEvents.class.getName() + ".call";

    private final CloudTrailService cloudTrail;
    private final AccountResolver accounts;
    private final RegionResolver regions;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;

    @Inject
    public GuardDutyCloudTrailEvents(CloudTrailService cloudTrail, AccountResolver accounts, RegionResolver regions,
                                     CurrentVertxRequest currentRequest, ObjectMapper mapper) {
        this.cloudTrail = cloudTrail;
        this.accounts = accounts;
        this.regions = regions;
        this.currentRequest = currentRequest;
        this.mapper = mapper;
    }

    /** A GuardDuty call a trail records, as its request carried it. */
    private record Call(String operation, Map<String, String> labels, MultivaluedMap<String, String> query,
                        JsonNode body) {
    }

    /** Notes the management call a request makes, with its members, before IAM enforcement and the controller. */
    @Override
    public void filter(ContainerRequestContext request) {
        if (!signedForGuardDuty(request.getHeaderString(HttpHeaders.AUTHORIZATION))) {
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
                    request.getUriInfo().getQueryParameters(), json(body)));
        } catch (RuntimeException e) {
            // The call is served either way; a record that could not be prepared is logged, not raised.
            LOG.warnv(e, "Failed to read the GuardDuty call for CloudTrail");
        }
    }

    /** Records the call {@link #filter(ContainerRequestContext)} noted, as {@code response} answered it. */
    @Override
    public void filter(ContainerRequestContext request, ContainerResponseContext response) {
        RoutingContext context = currentRequest.getCurrent();
        if (context == null || !(context.remove(CALL) instanceof Call call) || response.getStatus() >= 400) {
            return;
        }
        try {
            CloudTrailEventCatalog catalog = CloudTrailEventCatalog.of(SERVICE);
            boolean readOnly = catalog.isReadOnly(call.operation());
            ObjectNode result = readOnly ? null
                    : CloudTrailShapes.of(SERVICE).result(call.operation(), answer(response.getEntity()),
                            CloudTrailShapes.JsonStyle.AS_SENT);
            String authorization = request.getHeaderString(HttpHeaders.AUTHORIZATION);
            cloudTrail.emitManagementEvent(new CloudTrailService.ManagementEventInput(EVENT_SOURCE,
                    catalog.eventName(call.operation()), regions.resolveRegionFromAuth(authorization),
                    accounts.extractAccessKeyId(authorization), requestParameters(call), result, readOnly,
                    sourceIp(context), userAgent(context), null, null, null));
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
     * The record of a call IAM enforcement refused with {@code refusal} before GuardDuty ran it: its members,
     * {@code AccessDenied}, and for a write the refusal's message as its {@code responseElements}, as the 2024
     * records of refused GuardDuty calls show; null for a call that is not a management event.
     */
    @Override
    public CloudTrailService.ManagementEventInput refused(String operation, String accessKeyId, String region,
                                                          RoutingContext routingContext, Response refusal) {
        CloudTrailEventCatalog catalog = CloudTrailEventCatalog.of(SERVICE);
        if (!catalog.isManagementEvent(operation)) {
            return null;
        }
        Object noted = routingContext == null ? null : routingContext.remove(CALL);
        ObjectNode parameters = noted instanceof Call call && call.operation().equals(operation)
                ? requestParameters(call) : null;
        boolean readOnly = catalog.isReadOnly(operation);
        String message = refusalMessage(refusal);
        ObjectNode answer = readOnly || message == null ? null : mapper.createObjectNode().put("message", message);
        return new CloudTrailService.ManagementEventInput(EVENT_SOURCE, catalog.eventName(operation), region,
                accessKeyId, parameters, answer, readOnly, sourceIp(routingContext), userAgent(routingContext),
                null, REFUSED, null);
    }

    private static ObjectNode requestParameters(Call call) {
        return CloudTrailShapes.of(SERVICE).requestParameters(call.operation(), call.labels(), call.query(),
                call.body(), CloudTrailShapes.JsonStyle.AS_SENT);
    }

    /** The JSON a controller answered with, whatever form its entity takes; null when it answered nothing. */
    private JsonNode answer(Object entity) {
        if (entity == null) {
            return null;
        }
        if (entity instanceof JsonNode node) {
            return node;
        }
        if (entity instanceof String text) {
            return text.isBlank() ? null : json(text.getBytes(StandardCharsets.UTF_8));
        }
        if (entity instanceof byte[] bytes) {
            return json(bytes);
        }
        return mapper.valueToTree(entity);
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

    /** Whether a request is signed for GuardDuty, whose routes Macie's and S3's requests may also take. */
    private static boolean signedForGuardDuty(String authorization) {
        return authorization != null && authorization.contains("/" + SERVICE + "/aws4_request");
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
