package io.floci.aws.services.sns;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AccountResolver;
import io.floci.aws.core.common.AwsErrorResponse;
import io.floci.aws.core.common.AwsException;
import io.floci.aws.core.common.RequestSourceAddress;
import io.floci.aws.core.common.ServicePrincipals;
import io.floci.aws.core.common.XmlParser;
import io.floci.aws.services.cloudtrail.CloudTrailEventCatalog;
import io.floci.aws.services.cloudtrail.CloudTrailService;
import io.floci.aws.services.cloudtrail.CloudTrailShapes;
import io.floci.aws.services.cloudtrail.ManagementEventSource;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;

import java.util.Set;
import java.util.function.Supplier;

/**
 * Records SNS's control plane calls as CloudTrail management events: "AWS SNS logs the following SNS control plane
 * operations to CloudTrail as management events"
 * (https://docs.aws.amazon.com/sns/latest/dg/logging-using-cloudtrail.html). Which calls, and which are read-only, is
 * the vendored {@code aws/sns-cloudtrail-events.json} ({@link CloudTrailEventCatalog}). {@code Publish} and
 * {@code PublishBatch} are data events, which this does not record.
 *
 * <p>A call is recorded under its own name, over either protocol Floci serves SNS on (Query, JSON), whether it
 * succeeds, fails or is refused:
 * <ul>
 *   <li>{@code eventSource} {@code sns.amazonaws.com}, and {@code requestParameters} the request's members named with
 *   a lower first letter and typed as botocore's SNS model types them ({@code "name": "hello"}, the guide's
 *   {@code CreateTopic} example; {@code "returnSubscriptionArn": false}, a {@code Subscribe} of 2024), read from a
 *   Query form or a JSON body alike ({@link CloudTrailShapes}). The address an email subscription names is
 *   {@code "endpoint": "REDACTED"}, as that {@code Subscribe} record writes it.</li>
 *   <li>{@code responseElements} the answer in the same form ({@code "topicArn"}, {@code "subscriptionArn"}, 2024
 *   records of {@code CreateTopic} and {@code Subscribe}), null for a read-only call (the guide's {@code ListTopics}),
 *   for a call that answers nothing (the guide's {@code DeleteTopic}) and for a failed one.</li>
 *   <li>A failed call keeps its members, under the name of the error shape that answers its code
 *   ({@code "errorCode": "NotFoundException"} for a topic that does not exist, which SNS answers {@code NotFound}, a
 *   {@code GetTopicAttributes} of 2026); one IAM enforcement refuses is recorded as {@code AccessDenied} with
 *   {@code "requestParameters": null} and the refusal's message (refused {@code ListTopics} and
 *   {@code GetSMSAttributes}, 2024).</li>
 *   <li>"When you aren't logged in to Amazon Web Services (unauthenticated mode), CloudTrail does not log the
 *   ConfirmSubscription or Unsubscribe actions", such as a confirmation link followed from an email: an unsigned
 *   {@code ConfirmSubscription} or {@code Unsubscribe} is not recorded.</li>
 * </ul>
 */
@ApplicationScoped
public class SnsCloudTrailEvents implements ManagementEventSource {

    private static final Logger LOG = Logger.getLogger(SnsCloudTrailEvents.class);
    /** The IAM service prefix, which names the events and shapes files and SNS's credential scope. */
    private static final String SERVICE = "sns";
    private static final String EVENT_SOURCE = ServicePrincipals.of(SERVICE);
    /** The calls CloudTrail does not log when they are made without credentials. */
    private static final Set<String> UNLOGGED_WHEN_UNAUTHENTICATED = Set.of("ConfirmSubscription", "Unsubscribe");
    /** What a record writes in place of the address an email subscription names. */
    private static final String REDACTED = "REDACTED";

    private final CloudTrailService cloudTrail;
    private final AccountResolver accounts;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;

    @Inject
    public SnsCloudTrailEvents(CloudTrailService cloudTrail, AccountResolver accounts,
                               CurrentVertxRequest currentRequest, ObjectMapper mapper) {
        this.cloudTrail = cloudTrail;
        this.accounts = accounts;
        this.currentRequest = currentRequest;
        this.mapper = mapper;
    }

    /** Runs {@code call}, the JSON call {@code action} carrying {@code request}, and records it. */
    Response recordedJson(String action, JsonNode request, String region, Supplier<Response> call) {
        Response response;
        try {
            response = call.get();
        } catch (AwsException e) {
            record(action, region, shapes -> shapes.requestParameters(action, request), null, e.getErrorCode(),
                    e.getMessage());
            throw e;
        }
        if (response.getEntity() instanceof AwsErrorResponse failure) {
            record(action, region, shapes -> shapes.requestParameters(action, request), null, failure.type(),
                    failure.message());
        } else {
            JsonNode answer = response.getStatus() < 400 && response.getEntity() != null
                    ? mapper.valueToTree(response.getEntity()) : null;
            record(action, region, shapes -> shapes.requestParameters(action, request),
                    shapes -> answer == null ? null : shapes.result(action, answer), null, null);
        }
        return response;
    }

    /** Runs {@code call}, the Query call {@code action} carrying {@code params}, and records it. */
    Response recordedQuery(String action, MultivaluedMap<String, String> params, String region,
                           Supplier<Response> call) {
        Response response;
        try {
            response = call.get();
        } catch (AwsException e) {
            record(action, region, shapes -> shapes.requestParameters(action, params), null, e.getErrorCode(),
                    e.getMessage());
            throw e;
        }
        String xml = response.getEntity() instanceof String text ? text : null;
        if (response.getStatus() >= 400) {
            XmlParser.XmlElement error = xml == null ? null : XmlParser.extractElementTree(xml, "Error");
            record(action, region, shapes -> shapes.requestParameters(action, params), null,
                    error == null || error.child("Code") == null ? null : error.child("Code").text(),
                    error == null || error.child("Message") == null ? null : error.child("Message").text());
        } else {
            record(action, region, shapes -> shapes.requestParameters(action, params),
                    shapes -> xml == null ? null : shapes.result(action, xml), null, null);
        }
        return response;
    }

    @Override
    public String credentialScope() {
        return SERVICE;
    }

    /**
     * The record of a call IAM enforcement refused with {@code refusal} before SNS ran it, with
     * {@code "requestParameters": null} and the message the refusal answered with; null for a call that is not a
     * management event.
     */
    @Override
    public CloudTrailService.ManagementEventInput refused(String operation, String accessKeyId, String region,
                                                          RoutingContext routingContext, Response refusal) {
        if (!CloudTrailEventCatalog.of(SERVICE).isManagementEvent(operation)) {
            return null;
        }
        return event(operation, null, null, accessKeyId, region, routingContext, REFUSED, refusalMessage(refusal));
    }

    /** What a record reads from the request or the answer, given the service's shapes. */
    @FunctionalInterface
    private interface Read {
        ObjectNode from(CloudTrailShapes shapes);
    }

    private void record(String action, String region, Read parameters, Read result, String errorCode,
                        String errorMessage) {
        CloudTrailEventCatalog catalog = CloudTrailEventCatalog.of(SERVICE);
        if (!catalog.isManagementEvent(action)) {
            return;
        }
        RoutingContext context = currentRequest.getCurrent();
        HttpServerRequest request = context == null ? null : context.request();
        String authorization = request == null ? null : request.getHeader("Authorization");
        boolean signed = (authorization != null && !authorization.isBlank())
                || (request != null && request.getParam("X-Amz-Credential") != null);
        if (!signed && UNLOGGED_WHEN_UNAUTHENTICATED.contains(action)) {
            return;
        }
        try {
            CloudTrailShapes shapes = CloudTrailShapes.of(SERVICE);
            ObjectNode requestParameters = redacted(action, parameters.from(shapes));
            ObjectNode answered = errorCode == null && result != null && !catalog.isReadOnly(action)
                    ? result.from(shapes) : null;
            cloudTrail.emitManagementEvent(event(action, requestParameters, answered,
                    accounts.extractAccessKeyId(authorization), region, context, shapes.recordedErrorCode(errorCode),
                    errorMessage));
        } catch (RuntimeException e) {
            // The call is answered either way; a record that could not be written is logged, not raised.
            LOG.warnv(e, "Failed to record CloudTrail call {0}", action);
        }
    }

    /** {@code requestParameters} with the address an email subscription names replaced, as records write it. */
    private static ObjectNode redacted(String action, ObjectNode requestParameters) {
        if (requestParameters != null && "Subscribe".equals(action)
                && "email".equals(requestParameters.path("protocol").asText())
                && requestParameters.has("endpoint")) {
            requestParameters.put("endpoint", REDACTED);
        }
        return requestParameters;
    }

    private static CloudTrailService.ManagementEventInput event(String action, ObjectNode requestParameters,
                                                                ObjectNode result, String accessKeyId, String region,
                                                                RoutingContext context, String errorCode,
                                                                String errorMessage) {
        HttpServerRequest request = context == null ? null : context.request();
        String sourceIp = request == null ? null : RequestSourceAddress.of(request);
        String userAgent = request == null ? null : request.getHeader("User-Agent");
        return new CloudTrailService.ManagementEventInput(EVENT_SOURCE, action, region, accessKeyId,
                requestParameters, result, CloudTrailEventCatalog.of(SERVICE).isReadOnly(action), sourceIp, userAgent,
                null, errorCode, errorMessage);
    }
}
