package io.floci.aws.services.cloudwatch.logs;

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

import java.util.function.Supplier;

/**
 * Records CloudWatch Logs calls as CloudTrail management events: "CloudWatch Logs supports logging
 * the following actions as events in CloudTrail log files", followed by the list
 * (https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/logging_cw_api_calls_cwl.html). Which
 * those are, and which are read-only, is the vendored {@code aws/logs-cloudtrail-events.json}
 * ({@link CloudTrailEventCatalog}): the guide's list, and AWS's Service Reference's access level. A
 * call the list leaves out, such as {@code PutLogEvents}, is not recorded.
 *
 * <p>A call is recorded whether it succeeds, fails, or is refused by IAM enforcement, a trail or not,
 * since event history keeps every management event. The record
 * follows that page's {@code CreateExportTask} example: {@code eventSource}
 * {@code logs.amazonaws.com}, {@code requestParameters} and {@code responseElements} the request's
 * and the result's members as botocore's model names and types them ({@code "logGroupName"},
 * {@code "to": 123456789012}, {@code "taskId"}), and {@code "apiVersion": "20140328"}, which a 2022
 * {@code DeleteLogGroup} record carries too. {@code responseElements} is null for a read-only call,
 * for a call that answers nothing and for a failed one. A call another service makes for the caller,
 * such as an API Gateway integration, is recorded without {@code invokedBy}.
 */
@ApplicationScoped
public class LogsCloudTrailEvents implements ManagementEventSource {

    private static final Logger LOG = Logger.getLogger(LogsCloudTrailEvents.class);
    private static final String SERVICE = "logs";
    private static final String EVENT_SOURCE = ServicePrincipals.of(SERVICE);
    /** The API version CloudWatch Logs records carry: botocore's model is {@code logs/2014-03-28}. */
    private static final String API_VERSION = "20140328";

    private final CloudTrailService cloudTrail;
    private final AccountResolver accounts;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;

    @Inject
    public LogsCloudTrailEvents(CloudTrailService cloudTrail, AccountResolver accounts,
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
                    result = shapes.result(action, mapper.valueToTree(response.getEntity()));
                }
            }
            cloudTrail.emitManagementEvent(event(action, shapes.requestParameters(action, request),
                    accounts.extractAccessKeyId(authorization), region, currentRequest.getCurrent(), result,
                    errorCode, errorMessage));
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
     * The record of a call IAM enforcement refused with {@code refusal} before CloudWatch Logs ran it,
     * with {@code "requestParameters": null} as AWS records an authorization refusal and the code and
     * message the refusal answered with; null for a call that is not a management event.
     */
    @Override
    public CloudTrailService.ManagementEventInput refused(String operation, String accessKeyId, String region,
                                                          RoutingContext routingContext, Response refusal) {
        if (!CloudTrailEventCatalog.of(SERVICE).isManagementEvent(operation)) {
            return null;
        }
        return event(operation, null, accessKeyId, region, routingContext, null, REFUSED, refusalMessage(refusal));
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
