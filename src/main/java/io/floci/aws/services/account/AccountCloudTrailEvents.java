package io.floci.aws.services.account;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AccountResolver;
import io.floci.aws.core.common.AwsErrorResponse;
import io.floci.aws.core.common.AwsPartition;
import io.floci.aws.core.common.AwsPartitions;
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
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * Records Account Management calls as CloudTrail management events: "AWS CloudTrail logs all Account
 * Management API operations found in the API Reference section of this guide"
 * (https://docs.aws.amazon.com/accounts/latest/reference/monitoring-cloudtrail.html). Which calls, and which
 * are read-only, is the vendored {@code aws/account-cloudtrail-events.json} ({@link CloudTrailEventCatalog}):
 * the calls Floci serves, read-only as AWS's Service Reference gives their access level, as that page's
 * examples record GetAlternateContact ({@code "readOnly": true}), PutAlternateContact and
 * DeleteAlternateContact.
 *
 * <p>Account's API is REST-JSON, so a call is told by its route, and its record is written here, around the
 * controller that serves it, once IAM enforcement has let it through. It follows that page's examples:
 * <ul>
 *   <li>{@code eventSource} {@code account.amazonaws.com}, recorded in the Region Account's endpoint signs for
 *   in the caller's partition ({@code us-east-1} in {@code aws}), as a global service's event, whatever Region
 *   the caller named;</li>
 *   <li>{@code requestParameters} are the request's members with a lower first letter
 *   ({@code "alternateContactType"}), without the members botocore's model marks sensitive, but for
 *   PutAlternateContact, whose example keeps {@code name}, {@code emailAddress} and {@code title} and leaves
 *   out {@code phoneNumber};</li>
 *   <li>{@code responseElements} is always null: "The values returned by the operation aren't included in the
 *   logged information";</li>
 *   <li>a failed call keeps its members and is recorded under its error's type, with its message; one IAM
 *   enforcement refuses is recorded as {@code AccessDenied} with {@code "requestParameters": null}.</li>
 * </ul>
 */
@Provider
@Priority(Priorities.USER + 100)
public class AccountCloudTrailEvents implements ContainerRequestFilter, ContainerResponseFilter,
        ManagementEventSource {

    private static final Logger LOG = Logger.getLogger(AccountCloudTrailEvents.class);
    private static final String SERVICE = "account";
    private static final String EVENT_SOURCE = ServicePrincipals.of(SERVICE);
    private static final String CALL = AccountCloudTrailEvents.class.getName() + ".call";
    /** The sensitive members PutAlternateContact's example records all the same, by their model names. */
    private static final List<String> ALTERNATE_CONTACT_RECORDED = List.of("Name", "EmailAddress", "Title");

    private final CloudTrailService cloudTrail;
    private final AccountResolver accounts;
    private final RegionResolver regions;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;

    @Inject
    public AccountCloudTrailEvents(CloudTrailService cloudTrail, AccountResolver accounts, RegionResolver regions,
                                   CurrentVertxRequest currentRequest, ObjectMapper mapper) {
        this.cloudTrail = cloudTrail;
        this.accounts = accounts;
        this.regions = regions;
        this.currentRequest = currentRequest;
        this.mapper = mapper;
    }

    /** An Account call a trail records, as its request carried it. */
    private record Call(String operation, JsonNode body) {
    }

    /**
     * Notes the management call a request makes, with its members, before its controller reads them. A request
     * IAM enforcement refused never reaches here: its record is {@link #refused}'s.
     */
    @Override
    public void filter(ContainerRequestContext request) {
        if (!signedForAccount(request.getHeaderString(HttpHeaders.AUTHORIZATION))) {
            return;
        }
        try {
            String operation = IamActionRegistry.routedOperation(SERVICE, request);
            if (!CloudTrailEventCatalog.of(SERVICE).isManagementEvent(operation)) {
                return;
            }
            request.setProperty(CALL, new Call(operation, json(IamConditionContextResolver.bufferEntity(request))));
        } catch (RuntimeException e) {
            // The call is served either way; a record that could not be prepared is logged, not raised.
            LOG.warnv(e, "Failed to read the Account call for CloudTrail");
        }
    }

    /** Records the call {@link #filter(ContainerRequestContext)} noted, as {@code response} answered it. */
    @Override
    public void filter(ContainerRequestContext request, ContainerResponseContext response) {
        if (!(request.getProperty(CALL) instanceof Call call)) {
            return;
        }
        try {
            String errorCode = null;
            String errorMessage = null;
            if (response.getStatus() >= 400) {
                JsonNode error = error(response.getEntity());
                if (error == null) {
                    // A failure that names no error has no errorCode to be recorded under.
                    return;
                }
                errorCode = error.path("__type").asText();
                errorMessage = error.path("message").asText(null);
            }
            String authorization = request.getHeaderString(HttpHeaders.AUTHORIZATION);
            RoutingContext context = currentRequest.getCurrent();
            cloudTrail.emitManagementEvent(event(call.operation(), requestParameters(call),
                    accounts.extractAccessKeyId(authorization), regions.resolveRegionFromAuth(authorization),
                    context, errorCode, errorMessage));
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
     * The record of a call IAM enforcement refused with {@code refusal} before Account ran it, with
     * {@code "requestParameters": null} and, as {@link #REFUSED}, the message the refusal answered with; null for
     * a call that is not a management event.
     */
    @Override
    public CloudTrailService.ManagementEventInput refused(String operation, String accessKeyId, String region,
                                                          RoutingContext routingContext, Response refusal) {
        if (!CloudTrailEventCatalog.of(SERVICE).isManagementEvent(operation)) {
            return null;
        }
        return event(operation, null, accessKeyId, region, routingContext, REFUSED, refusalMessage(refusal));
    }

    /** The request's members as the record writes them; PutAlternateContact keeps the contact its example shows. */
    private ObjectNode requestParameters(Call call) {
        ObjectNode parameters = CloudTrailShapes.of(SERVICE).requestParameters(call.operation(), call.body());
        if (!"PutAlternateContact".equals(call.operation()) || call.body() == null || !call.body().isObject()) {
            return parameters;
        }
        ObjectNode read = parameters == null ? mapper.createObjectNode() : parameters;
        for (String member : ALTERNATE_CONTACT_RECORDED) {
            JsonNode value = call.body().get(member);
            if (value != null && value.isTextual()) {
                read.set(Character.toLowerCase(member.charAt(0)) + member.substring(1), value);
            }
        }
        return read.isEmpty() ? null : read;
    }

    private static CloudTrailService.ManagementEventInput event(String operation, ObjectNode requestParameters,
                                                                String accessKeyId, String region,
                                                                RoutingContext context, String errorCode,
                                                                String errorMessage) {
        CloudTrailEventCatalog catalog = CloudTrailEventCatalog.of(SERVICE);
        HttpServerRequest request = context == null ? null : context.request();
        // Recorded in the Region Account's endpoint signs for in the request's partition, as a global service's
        // event, which only a trail including global service events records.
        Optional<AwsPartition.GlobalEndpoint> global = AwsPartitions.forRegionOrCommercial(region)
                .globalEndpoint(SERVICE);
        return new CloudTrailService.ManagementEventInput(EVENT_SOURCE, catalog.eventName(operation),
                global.map(AwsPartition.GlobalEndpoint::signingRegion).orElse(region), accessKeyId,
                requestParameters, null, catalog.isReadOnly(operation),
                request == null ? null : RequestSourceAddress.of(request),
                request == null ? null : request.getHeader("User-Agent"), null, errorCode, errorMessage,
                global.isPresent(), null, null, null);
    }

    /** The error a failed call answered with, as {@code __type} and {@code message}; null when it names none. */
    private JsonNode error(Object entity) {
        if (entity instanceof AwsErrorResponse error) {
            return mapper.createObjectNode().put("__type", error.type()).put("message", error.message());
        }
        if (entity instanceof JsonNode node && node.hasNonNull("__type")) {
            return node;
        }
        return null;
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

    /** Whether a request is signed for Account, whose routes another service's requests may also take. */
    private static boolean signedForAccount(String authorization) {
        return authorization != null && authorization.contains("/" + SERVICE + "/aws4_request");
    }
}
