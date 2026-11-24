package io.floci.aws.services.eventbridge;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AccountResolver;
import io.floci.aws.core.common.AwsErrorResponse;
import io.floci.aws.core.common.AwsException;
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
import java.util.function.Supplier;

/**
 * Records EventBridge calls as CloudTrail management events: "All Amazon EventBridge API operations
 * except PutEvents and PutPartnerEvents are control plane operations"
 * (https://docs.aws.amazon.com/eventbridge/latest/userguide/logging-using-cloudtrail.html). Which
 * those are, and which are read-only, is the vendored {@code aws/events-cloudtrail-events.json}
 * ({@link CloudTrailEventCatalog}): every other operation of botocore's model, and AWS's Service
 * Reference's access level. {@code PutEvents} and {@code PutPartnerEvents}, data events, are not recorded.
 *
 * <p>A call is recorded whether it succeeds, fails, or is refused by IAM enforcement, a trail or not,
 * since event history keeps every management event. The record follows that page's {@code PutRule}
 * example and a {@code DeleteRule} record of 2024: {@code eventSource} {@code events.amazonaws.com},
 * {@code requestParameters} and {@code responseElements} the request's and the result's members as
 * botocore's model names and types them ({@code "name"}, {@code "eventPattern"}, {@code "ruleArn"}),
 * and {@code "apiVersion": "2015-10-07"}. A timestamp is written as the page's {@code PutPartnerEvents}
 * example writes its entry's {@code time} ({@code "Mar 7, 2026, 12:51:07 AM"}), and a member the model
 * marks sensitive, such as a connection's API key, password or client secret, is left out.
 * {@code responseElements} is null for a read-only call, for a call that answers nothing and for a failed
 * one. A call IAM enforcement refuses is recorded as records of 2024 show one: {@code AccessDenied},
 * {@code "requestParameters": null} and no {@code apiVersion}. A call another service makes for the
 * caller, such as an API Gateway integration, is recorded without {@code invokedBy}.
 *
 * <p>Only the calls a client makes are recorded: the events CloudTrail itself puts on the default bus
 * ({@code CloudTrailEventBridgeDelivery}) reach EventBridge without a call, so delivering a recorded
 * call records nothing more.
 */
@ApplicationScoped
public class EventBridgeCloudTrailEvents implements ManagementEventSource {

    private static final Logger LOG = Logger.getLogger(EventBridgeCloudTrailEvents.class);
    private static final String SERVICE = "events";
    private static final String EVENT_SOURCE = ServicePrincipals.of(SERVICE);
    /** The API version EventBridge records carry: botocore's model is {@code events/2015-10-07}. */
    private static final String API_VERSION = "2015-10-07";
    private static final CloudTrailShapes.JsonStyle STYLE = new CloudTrailShapes.JsonStyle(false,
            DateTimeFormatter.ofPattern("MMM d, yyyy, h:mm:ss a", Locale.US).withZone(ZoneOffset.UTC));

    private final CloudTrailService cloudTrail;
    private final AccountResolver accounts;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;

    @Inject
    public EventBridgeCloudTrailEvents(CloudTrailService cloudTrail, AccountResolver accounts,
                                       CurrentVertxRequest currentRequest, ObjectMapper mapper) {
        this.cloudTrail = cloudTrail;
        this.accounts = accounts;
        this.currentRequest = currentRequest;
        this.mapper = mapper;
    }

    /** Runs {@code call}, the call {@code action} signed with {@code authorization}, and records it. */
    public Response recorded(String action, JsonNode request, String region, String authorization,
                             Supplier<Response> call) {
        Response response;
        try {
            response = call.get();
        } catch (AwsException e) {
            record(action, request, region, authorization, null, e);
            throw e;
        }
        record(action, request, region, authorization, response, null);
        return response;
    }

    private void record(String action, JsonNode request, String region, String authorization, Response response,
                        AwsException error) {
        CloudTrailEventCatalog catalog = CloudTrailEventCatalog.of(SERVICE);
        if (!catalog.isManagementEvent(action)) {
            return;
        }
        try {
            CloudTrailShapes shapes = CloudTrailShapes.of(SERVICE);
            String errorCode = error == null ? null : error.jsonType();
            String errorMessage = error == null ? null : error.getMessage();
            ObjectNode result = null;
            if (error == null && response != null) {
                if (response.getEntity() instanceof AwsErrorResponse failure) {
                    errorCode = failure.type();
                    errorMessage = failure.message();
                } else if (response.getStatus() < 400 && response.getEntity() != null && !catalog.isReadOnly(action)) {
                    result = shapes.result(action, mapper.valueToTree(response.getEntity()), STYLE);
                }
            }
            cloudTrail.emitManagementEvent(event(action, shapes.requestParameters(action, request, STYLE),
                    accounts.extractAccessKeyId(authorization), region, currentRequest.getCurrent(), result,
                    errorCode, errorMessage, API_VERSION));
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
     * The record of a call IAM enforcement refused with {@code refusal} before EventBridge ran it, with
     * {@code "requestParameters": null}, the message the refusal answered with and no {@code apiVersion},
     * as 2024 records of refused DeleteRule, DisableRule, ListRules and RemoveTargets calls show; null for
     * a call that is not a management event.
     */
    @Override
    public CloudTrailService.ManagementEventInput refused(String operation, String accessKeyId, String region,
                                                          RoutingContext routingContext, Response refusal) {
        if (!CloudTrailEventCatalog.of(SERVICE).isManagementEvent(operation)) {
            return null;
        }
        return event(operation, null, accessKeyId, region, routingContext, null, REFUSED, refusalMessage(refusal),
                null);
    }

    private static CloudTrailService.ManagementEventInput event(String action, ObjectNode requestParameters,
                                                                String accessKeyId, String region,
                                                                RoutingContext context, ObjectNode result,
                                                                String errorCode, String errorMessage,
                                                                String apiVersion) {
        HttpServerRequest request = context == null ? null : context.request();
        String sourceIp = request == null ? null : RequestSourceAddress.of(request);
        String userAgent = request == null ? null : request.getHeader("User-Agent");
        return new CloudTrailService.ManagementEventInput(EVENT_SOURCE, action, region, accessKeyId,
                requestParameters, result, CloudTrailEventCatalog.of(SERVICE).isReadOnly(action), sourceIp,
                userAgent, null, errorCode, errorMessage, false, null, null, null, apiVersion);
    }
}
