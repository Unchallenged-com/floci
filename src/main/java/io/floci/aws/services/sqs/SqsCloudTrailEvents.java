package io.floci.aws.services.sqs;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AccountResolver;
import io.floci.aws.core.common.AwsException;
import io.floci.aws.core.common.ServicePrincipals;
import io.floci.aws.core.common.VendoredResources;
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

import java.util.HashSet;
import java.util.Set;

/**
 * Records SQS's control plane calls as CloudTrail management events, as the SQS Developer Guide
 * says CloudTrail does: "Amazon SQS logs the following control plane operations to CloudTrail as
 * management events"
 * (https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/logging-using-cloudtrail.html).
 * Which calls those are, and which of them are read-only, is the vendored
 * {@code aws/sqs-cloudtrail-events.json}: the guide's list, and AWS's Service Reference's access
 * level ({@code ListMessageMoveTasks} is the only read-only one). Every other SQS call is a data
 * event, which this does not record.
 *
 * <p>A call is recorded whether it succeeds, fails, or is refused by IAM enforcement. The record
 * follows that page's event example: {@code eventSource} {@code sqs.amazonaws.com},
 * {@code awsRegion} the queue's Region, and {@code requestParameters} and {@code responseElements}
 * the request's and the result's members named with a lower first letter ({@code queueUrl},
 * {@code mD5OfMessageBody}), as botocore's SQS model types them ({@link CloudTrailShapes}). The
 * result is null for a read-only call, as CloudTrail's record contents give {@code responseElements}
 * "For readOnly APIs, this field is null", for a call that answers nothing and for a failed one
 * (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html).
 * An error is recorded under its shape's name ({@code QueueDoesNotExist}), the {@code __type} the
 * JSON protocol answers with.
 *
 * <p>Only calls made over SQS's JSON protocol are recorded: botocore's SQS model no longer carries
 * the Query protocol's member names, so a Query request cannot be read as the model's members.
 */
@ApplicationScoped
public class SqsCloudTrailEvents implements ManagementEventSource {

    private static final Logger LOG = Logger.getLogger(SqsCloudTrailEvents.class);
    private static final String EVENT_SOURCE = ServicePrincipals.of("sqs");
    private static final String RESOURCE_NAME = "aws/sqs-cloudtrail-events.json";

    /** The vendored file: the calls CloudTrail records as management events, and the read-only ones. */
    record Catalog(Set<String> managementEvents, Set<String> readOnlyActions) {
    }

    private static final class Holder {
        static final Catalog CATALOG = VendoredResources.read(RESOURCE_NAME, "SQS CloudTrail events",
                in -> catalog(new ObjectMapper().readTree(in)));
    }

    private final CloudTrailService cloudTrail;
    private final AccountResolver accounts;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;

    @Inject
    public SqsCloudTrailEvents(CloudTrailService cloudTrail, AccountResolver accounts,
                               CurrentVertxRequest currentRequest, ObjectMapper mapper) {
        this.cloudTrail = cloudTrail;
        this.accounts = accounts;
        this.currentRequest = currentRequest;
        this.mapper = mapper;
    }

    /** Whether CloudTrail records {@code action} as a management event. */
    static boolean isManagementEvent(String action) {
        return action != null && Holder.CATALOG.managementEvents().contains(action);
    }

    /** Whether CloudTrail records {@code action} as read-only. */
    static boolean isReadOnly(String action) {
        return action != null && Holder.CATALOG.readOnlyActions().contains(action);
    }

    /**
     * Records the JSON call {@code response} answered, or that failed with {@code error} when it is
     * set.
     */
    void record(String action, JsonNode request, String region, String authorization, Response response,
                AwsException error) {
        if (!isManagementEvent(action) || !cloudTrail.hasTrails()) {
            return;
        }
        try {
            CloudTrailShapes shapes = CloudTrailShapes.of("sqs");
            boolean answered = error == null && response != null && response.getStatus() < 400;
            ObjectNode result = answered && !isReadOnly(action) && response.getEntity() != null
                    ? shapes.result(action, mapper.valueToTree(response.getEntity())) : null;
            cloudTrail.emitManagementEvent(event(action, shapes.requestParameters(action, request),
                    accounts.extractAccessKeyId(authorization), region, request(currentRequest.getCurrent()), result,
                    error == null ? null : error.jsonType(), error == null ? null : error.getMessage()));
        } catch (RuntimeException e) {
            // The call is answered either way; a record that could not be written is logged, not raised.
            LOG.warnv(e, "Failed to record CloudTrail call {0}", action);
        }
    }

    @Override
    public String credentialScope() {
        return "sqs";
    }

    /**
     * The record of a call IAM enforcement refused before SQS ran it, with
     * {@code "requestParameters": null} as AWS records an authorization refusal; null for a call
     * that is not a management event.
     */
    @Override
    public CloudTrailService.ManagementEventInput refused(String operation, String accessKeyId, String region,
                                                          RoutingContext routingContext, String errorCode,
                                                          String errorMessage) {
        if (!isManagementEvent(operation)) {
            return null;
        }
        return event(operation, null, accessKeyId, region, request(routingContext), null, errorCode, errorMessage);
    }

    private static CloudTrailService.ManagementEventInput event(String action, ObjectNode requestParameters,
                                                                String accessKeyId, String region,
                                                                HttpServerRequest request, ObjectNode result,
                                                                String errorCode, String errorMessage) {
        String sourceIp = request == null || request.remoteAddress() == null ? null : request.remoteAddress().host();
        String userAgent = request == null ? null : request.getHeader("User-Agent");
        return new CloudTrailService.ManagementEventInput(EVENT_SOURCE, action, region, accessKeyId,
                requestParameters, result, isReadOnly(action), sourceIp, userAgent, null, errorCode, errorMessage);
    }

    private static HttpServerRequest request(RoutingContext routingContext) {
        return routingContext == null ? null : routingContext.request();
    }

    private static Catalog catalog(JsonNode root) {
        Set<String> events = names(root.path("managementEvents"));
        if (events.isEmpty()) {
            throw new IllegalStateException(RESOURCE_NAME + " carries no managementEvents");
        }
        Set<String> readOnly = names(root.path("readOnlyActions"));
        if (!events.containsAll(readOnly)) {
            throw new IllegalStateException(RESOURCE_NAME + " lists a read-only action that is not a management event");
        }
        return new Catalog(Set.copyOf(events), Set.copyOf(readOnly));
    }

    private static Set<String> names(JsonNode array) {
        Set<String> names = new HashSet<>();
        for (JsonNode name : array) {
            names.add(name.asText());
        }
        return names;
    }
}
