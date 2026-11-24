package io.floci.aws.services.dynamodb;

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
import java.util.Set;
import java.util.concurrent.Callable;

/**
 * Records DynamoDB's and DynamoDB Streams' control plane calls as CloudTrail management events: "CloudTrail
 * captures all API calls for DynamoDB as events", and "The following API actions are logged by default as
 * events in CloudTrail files", followed by the DynamoDB and the DynamoDB Streams lists
 * (https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/logging-using-cloudtrail.html). Which
 * those are, and which are read-only, is the vendored {@code aws/dynamodb-cloudtrail-events.json}
 * ({@link CloudTrailEventCatalog}): the guide's lists, the other calls Floci serves that its data plane list
 * leaves out ({@code UpdateContinuousBackups}, {@code ExportTableToPointInTime}, {@code PutResourcePolicy}),
 * and AWS's Service Reference's access level. The item calls, PartiQL, transactions and the Streams reads
 * ({@code GetRecords}, {@code GetShardIterator}) are data events, which this does not record.
 *
 * <p>A call is recorded whether it succeeds, fails, or is refused by IAM enforcement, a trail or not, since
 * event history keeps every management event. The record follows the log entries the guide shows
 * (https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/understanding-ddb-log-entries.html):
 * {@code eventSource} {@code dynamodb.amazonaws.com}, a Streams call's too, as its {@code GetRecords} entry
 * shows, {@code "apiVersion": "2012-08-10"}, and {@code requestParameters} and {@code responseElements} the
 * request's and the result's members with a lower first letter ({@code "tableName"},
 * {@code "tableDescription"}), as botocore's models type them ({@link CloudTrailShapes}), timestamps in the
 * result written as its {@code UpdateTable} entry writes {@code "creationDateTime": "May 3, 2015 11:34:14 PM"}.
 * {@code responseElements} is null for a read-only call, for a call that answers nothing and for a failed
 * one. An error is recorded under its shape's name ({@code ResourceNotFoundException}), as the guide's
 * {@code UpdateItem} entry records {@code ConditionalCheckFailedException}.
 *
 * <p>Only calls made over DynamoDB's JSON protocol are recorded, under its current API version.
 */
@ApplicationScoped
public class DynamoDbCloudTrailEvents implements ManagementEventSource {

    private static final Logger LOG = Logger.getLogger(DynamoDbCloudTrailEvents.class);
    private static final String SERVICE = "dynamodb";
    private static final String STREAMS_SHAPES = "dynamodbstreams";
    private static final String EVENT_SOURCE = ServicePrincipals.of(SERVICE);
    /** The API version the guide's log entries carry, botocore's {@code dynamodb/2012-08-10}. */
    private static final String API_VERSION = "2012-08-10";
    /** The DynamoDB Streams calls the guide lists, whose members are its model's. */
    private static final Set<String> STREAMS_CALLS = Set.of("DescribeStream", "ListStreams");
    /** The guide's UpdateTable entry: {@code "creationDateTime": "May 3, 2015 11:34:14 PM"}. */
    private static final CloudTrailShapes.JsonStyle RESULT_STYLE = new CloudTrailShapes.JsonStyle(false,
            DateTimeFormatter.ofPattern("MMM d, yyyy h:mm:ss a", Locale.US).withZone(ZoneOffset.UTC));

    private final CloudTrailService cloudTrail;
    private final RequestContext requestContext;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;

    @Inject
    public DynamoDbCloudTrailEvents(CloudTrailService cloudTrail, RequestContext requestContext,
                                    CurrentVertxRequest currentRequest, ObjectMapper mapper) {
        this.cloudTrail = cloudTrail;
        this.requestContext = requestContext;
        this.currentRequest = currentRequest;
        this.mapper = mapper;
    }

    /** Runs {@code call}, the JSON call {@code action} a client made, and records it. */
    public Response recorded(String action, JsonNode request, String region, Callable<Response> call)
            throws Exception {
        Response response;
        try {
            response = call.call();
        } catch (AwsException e) {
            record(action, request, region, null, e);
            throw e;
        }
        record(action, request, region, response, null);
        return response;
    }

    private void record(String action, JsonNode request, String region, Response response, AwsException error) {
        CloudTrailEventCatalog catalog = CloudTrailEventCatalog.of(SERVICE);
        if (!catalog.isManagementEvent(action)) {
            return;
        }
        try {
            CloudTrailShapes shapes = CloudTrailShapes.of(STREAMS_CALLS.contains(action) ? STREAMS_SHAPES : SERVICE);
            String errorCode = error == null ? null : error.jsonType();
            String errorMessage = error == null ? null : error.getMessage();
            ObjectNode result = null;
            if (error == null && response != null) {
                JsonNode answer = response.getEntity() == null ? null : mapper.valueToTree(response.getEntity());
                if (response.getStatus() >= 400) {
                    errorCode = errorType(answer);
                    errorMessage = errorMessage(answer);
                } else if (answer != null && !catalog.isReadOnly(action)) {
                    result = shapes.result(action, answer, RESULT_STYLE);
                }
            }
            cloudTrail.emitManagementEvent(event(action, shapes.requestParameters(action, request),
                    requestContext.getAccessKeyId(), region, currentRequest.getCurrent(), result, errorCode,
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
     * The record of a call IAM enforcement refused with {@code refusal} before DynamoDB ran it, with
     * {@code "requestParameters": null} as AWS records an authorization refusal and the message the refusal
     * answered with; null for a call that is not a management event.
     */
    @Override
    public CloudTrailService.ManagementEventInput refused(String operation, String accessKeyId, String region,
                                                          RoutingContext routingContext, Response refusal) {
        if (!CloudTrailEventCatalog.of(SERVICE).isManagementEvent(operation)) {
            return null;
        }
        return event(operation, null, accessKeyId, region, routingContext, null, REFUSED, refusalMessage(refusal));
    }

    /** The error shape a DynamoDB error body names, without the namespace its {@code __type} carries. */
    private static String errorType(JsonNode answer) {
        String type = answer == null ? null : answer.path("__type").asText(null);
        return type == null ? null : type.substring(type.lastIndexOf('#') + 1);
    }

    private static String errorMessage(JsonNode answer) {
        if (answer == null) {
            return null;
        }
        String message = answer.path("message").asText(null);
        return message != null ? message : answer.path("Message").asText(null);
    }

    private static CloudTrailService.ManagementEventInput event(String action, ObjectNode requestParameters,
                                                                String accessKeyId, String region,
                                                                RoutingContext context, ObjectNode result,
                                                                String errorCode, String errorMessage) {
        HttpServerRequest request = context == null ? null : context.request();
        String sourceIp = request == null ? null : RequestSourceAddress.of(request);
        String userAgent = request == null ? null : request.getHeader("User-Agent");
        return new CloudTrailService.ManagementEventInput(EVENT_SOURCE, action, region, accessKeyId,
                requestParameters, result, CloudTrailEventCatalog.of(SERVICE).isReadOnly(action), sourceIp,
                userAgent, null, errorCode, errorMessage, false, null, null, null, API_VERSION);
    }
}
