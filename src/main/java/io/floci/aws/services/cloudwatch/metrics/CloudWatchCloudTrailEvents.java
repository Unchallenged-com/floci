package io.floci.aws.services.cloudwatch.metrics;

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

import java.util.function.Supplier;

/**
 * Records CloudWatch's management calls as CloudTrail management events: "CloudWatch supports logging the following
 * actions as events in CloudTrail log files"
 * (https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/logging_cw_api_calls.html). Which calls, and which
 * are read-only, is the vendored {@code aws/cloudwatch-cloudtrail-events.json} ({@link CloudTrailEventCatalog}): the
 * guide's list, with {@code DeleteAlarms}, which records of 2024 show and the guide names {@code DeleteAlarmActions}.
 * Its metric calls ({@code PutMetricData}, {@code GetMetricData}) are data events, which this does not record.
 *
 * <p>A call is recorded under its own name, over any of the protocols CloudWatch serves (Query, JSON, CBOR), whether
 * it succeeds, fails or is refused:
 * <ul>
 *   <li>{@code eventSource} {@code monitoring.amazonaws.com}, and {@code requestParameters} the request's members
 *   named with a lower first letter and typed as botocore's CloudWatch model types them, a list as a JSON array
 *   ({@code "alarmNames": ["cpu-mon"]}, 2024; {@code "threshold": 50.0, "period": 60}, the guide's example), read from
 *   a Query form or a JSON body alike ({@link CloudTrailShapes}).</li>
 *   <li>{@code responseElements} the answer in the same form, null for a read-only call (2025 records of
 *   {@code DescribeAlarms} and {@code DescribeAlarmsForMetric}), for a call that answers nothing ({@code DeleteAlarms},
 *   2024; {@code PutMetricAlarm}, the guide's example) and for a failed one.</li>
 *   <li>A failed call keeps its members, under the code it answered; one IAM enforcement refuses is recorded as
 *   {@code AccessDenied} with {@code "requestParameters": null} (a refused {@code DeleteAlarms}, 2024).</li>
 * </ul>
 */
@ApplicationScoped
public class CloudWatchCloudTrailEvents implements ManagementEventSource {

    private static final Logger LOG = Logger.getLogger(CloudWatchCloudTrailEvents.class);
    /**
     * The IAM service prefix, which names the events and shapes files and the credential scope IAM enforcement
     * resolves CloudWatch's signing name {@code monitoring} to.
     */
    private static final String SERVICE = "cloudwatch";
    private static final String EVENT_SOURCE = ServicePrincipals.of("monitoring");

    private final CloudTrailService cloudTrail;
    private final AccountResolver accounts;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;

    @Inject
    public CloudWatchCloudTrailEvents(CloudTrailService cloudTrail, AccountResolver accounts,
                                      CurrentVertxRequest currentRequest, ObjectMapper mapper) {
        this.cloudTrail = cloudTrail;
        this.accounts = accounts;
        this.currentRequest = currentRequest;
        this.mapper = mapper;
    }

    /** Runs {@code call}, the JSON or CBOR call {@code action} carrying {@code request}, and records it. */
    Response recordedJson(String action, JsonNode request, String region, Supplier<Response> call) {
        Response response;
        try {
            response = call.get();
        } catch (AwsException e) {
            record(action, region, shapes -> shapes.requestParameters(action, request), null, e.jsonType(),
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
     * The record of a call IAM enforcement refused with {@code refusal} before CloudWatch ran it, with
     * {@code "requestParameters": null}, as a refused {@code DeleteAlarms} of 2024 shows, and the code and
     * message the refusal answered with; null for a call that is not a management event.
     */
    @Override
    public CloudTrailService.ManagementEventInput refused(String operation, String accessKeyId, String region,
                                                          RoutingContext routingContext, Response refusal) {
        CloudTrailEventCatalog catalog = CloudTrailEventCatalog.of(SERVICE);
        String action = normalized(operation);
        if (!catalog.isManagementEvent(action)) {
            return null;
        }
        return event(action, null, null, accessKeyId, region, routingContext, REFUSED, refusalMessage(refusal));
    }

    /** What a record reads from the request or the answer, given the service's shapes. */
    @FunctionalInterface
    private interface Read {
        ObjectNode from(CloudTrailShapes shapes);
    }

    private void record(String operation, String region, Read parameters, Read result, String errorCode,
                        String errorMessage) {
        CloudTrailEventCatalog catalog = CloudTrailEventCatalog.of(SERVICE);
        String action = normalized(operation);
        if (!catalog.isManagementEvent(action)) {
            return;
        }
        try {
            CloudTrailShapes shapes = CloudTrailShapes.of(SERVICE);
            ObjectNode answered = errorCode == null && result != null && !catalog.isReadOnly(action)
                    ? result.from(shapes) : null;
            RoutingContext context = currentRequest.getCurrent();
            HttpServerRequest request = context == null ? null : context.request();
            String authorization = request == null ? null : request.getHeader("Authorization");
            cloudTrail.emitManagementEvent(event(action, parameters.from(shapes), answered,
                    accounts.extractAccessKeyId(authorization), region, context, errorCode, errorMessage));
        } catch (RuntimeException e) {
            // The call is answered either way; a record that could not be written is logged, not raised.
            LOG.warnv(e, "Failed to record CloudTrail call {0}", action);
        }
    }

    /** The operation as the model names it: a JSON or CBOR call may give it a lower first letter. */
    private static String normalized(String action) {
        return action == null || action.isEmpty() ? action
                : Character.toUpperCase(action.charAt(0)) + action.substring(1);
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
