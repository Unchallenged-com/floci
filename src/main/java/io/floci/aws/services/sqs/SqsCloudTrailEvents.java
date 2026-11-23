package io.floci.aws.services.sqs;

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


/**
 * Records SQS's control plane calls as CloudTrail management events, as the SQS Developer Guide
 * says CloudTrail does: "Amazon SQS logs the following control plane operations to CloudTrail as
 * management events"
 * (https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/logging-using-cloudtrail.html).
 * Which calls those are, and which of them are read-only, is the vendored
 * {@code aws/sqs-cloudtrail-events.json} ({@link CloudTrailEventCatalog}): the guide's list, and AWS's
 * Service Reference's access level ({@code ListMessageMoveTasks} is the only read-only one). Every other SQS call is a data
 * event, which this does not record.
 *
 * <p>A call is recorded whether it succeeds, fails, or is refused by IAM enforcement, a trail or not,
 * since event history keeps every management event. The record
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

    private final CloudTrailService cloudTrail;
    private final RequestContext requestContext;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;

    @Inject
    public SqsCloudTrailEvents(CloudTrailService cloudTrail, RequestContext requestContext,
                               CurrentVertxRequest currentRequest, ObjectMapper mapper) {
        this.cloudTrail = cloudTrail;
        this.requestContext = requestContext;
        this.currentRequest = currentRequest;
        this.mapper = mapper;
    }

    /** Whether CloudTrail records {@code action} as a management event. */
    static boolean isManagementEvent(String action) {
        return CloudTrailEventCatalog.of("sqs").isManagementEvent(action);
    }

    /** Whether CloudTrail records {@code action} as read-only. */
    static boolean isReadOnly(String action) {
        return CloudTrailEventCatalog.of("sqs").isReadOnly(action);
    }

    /**
     * Records the JSON call {@code response} answered, or that failed with {@code error} when it is
     * set, as the caller the request was signed by.
     */
    void record(String action, JsonNode request, String region, Response response, AwsException error) {
        if (!isManagementEvent(action)) {
            return;
        }
        try {
            CloudTrailShapes shapes = CloudTrailShapes.of("sqs");
            boolean answered = error == null && response != null && response.getStatus() < 400;
            ObjectNode result = answered && !isReadOnly(action) && response.getEntity() != null
                    ? shapes.result(action, mapper.valueToTree(response.getEntity())) : null;
            cloudTrail.emitManagementEvent(event(action, shapes.requestParameters(action, request),
                    requestContext.getAccessKeyId(), region, request(currentRequest.getCurrent()), result,
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
     * The record of a call IAM enforcement refused with {@code refusal} before SQS ran it, with
     * {@code "requestParameters": null} as AWS records an authorization refusal and, as {@link #REFUSED}, the
     * message the refusal answered with; null for a call that is not a management event.
     */
    @Override
    public CloudTrailService.ManagementEventInput refused(String operation, String accessKeyId, String region,
                                                          RoutingContext routingContext, Response refusal) {
        if (!isManagementEvent(operation)) {
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
        return new CloudTrailService.ManagementEventInput(EVENT_SOURCE, action, region, accessKeyId,
                requestParameters, result, isReadOnly(action), sourceIp, userAgent, null, errorCode, errorMessage);
    }

    private static HttpServerRequest request(RoutingContext routingContext) {
        return routingContext == null ? null : routingContext.request();
    }
}
