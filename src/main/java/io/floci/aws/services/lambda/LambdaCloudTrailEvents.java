package io.floci.aws.services.lambda;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AccountResolver;
import io.floci.aws.core.common.AwsErrorResponse;
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
import java.util.Set;

/**
 * Records Lambda's management calls as CloudTrail management events: "Lambda supports logging the
 * following actions as management events in CloudTrail log files"
 * (https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html). Which calls, which are
 * read-only and the name each record gives its call ({@code CreateFunction20150331}) are the vendored
 * {@code aws/lambda-cloudtrail-events.json} ({@link CloudTrailEventCatalog}).
 *
 * <p>Lambda's API is REST-JSON, so a call is told by its route, and its record is written here, around
 * the controller that serves it, once IAM enforcement has let it through:
 * <ul>
 *   <li>{@code requestParameters} are the members the call carries in its path, its query and its body,
 *   each with a lower first letter and typed as botocore's Lambda model types it
 *   ({@code "functionName"}, {@code "maxItems": 10000}), without the members the model marks sensitive:
 *   "The {@code Environment} and {@code ZipFile} parameters are omitted from the CloudTrail logs", so a
 *   record writes {@code "code": {}} and {@code "environment": {}}, as 2024 records of CreateFunction and
 *   UpdateFunctionConfiguration do. Those two always write {@code "environment": {}}: UpdateFunctionConfiguration's
 *   2024 record does for a request that sends no environment.</li>
 *   <li>UpdateFunctionCode's records (2024, 2023, 2022) name the function by its ARN whatever the request
 *   names it by, add its {@code fullyQualifiedArn} ({@code arnPrefix}, {@code relativeId} and an empty
 *   {@code functionQualifier}), and {@code "dryRun": false} when the request leaves it out.</li>
 *   <li>{@code responseElements} is the call's answer in the same form, null for a read-only call, a call
 *   that answers nothing (DeleteFunction, RemovePermission) and a failed one. A function's configuration
 *   always writes {@code "environment": {}}, as the CreateFunction, UpdateFunctionCode and
 *   UpdateFunctionConfiguration records do for functions without one.</li>
 *   <li>PublishLayerVersion's record (2026) carries {@code "additionalEventData": {"signatureStatus": "VALID"}}.</li>
 *   <li>A failed call keeps its members and is recorded under its error's type
 *   ({@code ResourceNotFoundException}, 2026); one IAM enforcement refuses is recorded as
 *   {@code AccessDenied} with {@code "requestParameters": null}, as 2024 records of refused
 *   AddPermission, CreateFunction and UpdateFunctionCode calls show.</li>
 * </ul>
 */
@Provider
@Priority(Priorities.USER + 100)
public class LambdaCloudTrailEvents implements ContainerRequestFilter, ContainerResponseFilter, ManagementEventSource {

    private static final Logger LOG = Logger.getLogger(LambdaCloudTrailEvents.class);
    private static final String SERVICE = "lambda";
    private static final String EVENT_SOURCE = ServicePrincipals.of(SERVICE);
    private static final String CALL = LambdaCloudTrailEvents.class.getName() + ".call";
    /** The calls that answer with a function's configuration, which a record writes with {@code "environment": {}}. */
    private static final Set<String> CONFIGURATION_ANSWERS = Set.of("CreateFunction", "PublishVersion",
            "UpdateFunctionCode", "UpdateFunctionConfiguration");
    /** The calls whose {@code requestParameters} always carry {@code "environment": {}}. */
    private static final Set<String> ENVIRONMENT_REQUESTS = Set.of("CreateFunction", "UpdateFunctionConfiguration");

    private final CloudTrailService cloudTrail;
    private final AccountResolver accounts;
    private final RegionResolver regions;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;

    @Inject
    public LambdaCloudTrailEvents(CloudTrailService cloudTrail, AccountResolver accounts, RegionResolver regions,
                                  CurrentVertxRequest currentRequest, ObjectMapper mapper) {
        this.cloudTrail = cloudTrail;
        this.accounts = accounts;
        this.regions = regions;
        this.currentRequest = currentRequest;
        this.mapper = mapper;
    }

    /** A Lambda call a trail records, as its request carried it. */
    private record Call(String operation, Map<String, String> labels, MultivaluedMap<String, String> query,
                        JsonNode body) {
    }

    /**
     * Notes the management call a request makes, with its members, before its controller reads them. A request
     * IAM enforcement refused never reaches here: its record is {@link #refused}'s.
     */
    @Override
    public void filter(ContainerRequestContext request) {
        if (!signedForLambda(request.getHeaderString(HttpHeaders.AUTHORIZATION))) {
            return;
        }
        try {
            String operation = IamActionRegistry.routedOperation(SERVICE, request);
            if (!CloudTrailEventCatalog.of(SERVICE).isManagementEvent(operation)) {
                return;
            }
            byte[] body = IamConditionContextResolver.bufferEntity(request);
            request.setProperty(CALL, new Call(operation, IamActionRegistry.pathLabels(SERVICE, request),
                    request.getUriInfo().getQueryParameters(), json(body)));
        } catch (RuntimeException e) {
            // The call is served either way; a record that could not be prepared is logged, not raised.
            LOG.warnv(e, "Failed to read the Lambda call for CloudTrail");
        }
    }

    /** Records the call {@link #filter(ContainerRequestContext)} noted, as {@code response} answered it. */
    @Override
    public void filter(ContainerRequestContext request, ContainerResponseContext response) {
        if (!(request.getProperty(CALL) instanceof Call call)) {
            return;
        }
        try {
            CloudTrailEventCatalog catalog = CloudTrailEventCatalog.of(SERVICE);
            CloudTrailShapes shapes = CloudTrailShapes.of(SERVICE);
            String operation = call.operation();
            JsonNode answer = answer(response.getEntity());
            String errorCode = null;
            String errorMessage = null;
            if (response.getStatus() >= 400) {
                errorCode = answer == null ? null : answer.path("__type").asText(null);
                errorMessage = answer == null ? null : answer.path("message").asText(null);
            }
            ObjectNode parameters = shapes.requestParameters(operation, call.labels(), call.query(), call.body(),
                    CloudTrailShapes.JsonStyle.AS_SENT);
            parameters = requestParameters(operation, parameters, errorCode == null ? answer : null);
            ObjectNode result = null;
            if (errorCode == null && !catalog.isReadOnly(operation)) {
                result = shapes.result(operation, answer, CloudTrailShapes.JsonStyle.AS_SENT);
                if (result != null && CONFIGURATION_ANSWERS.contains(operation) && !result.has("environment")) {
                    result.putObject("environment");
                }
            }
            ObjectNode additional = null;
            if (errorCode == null && "PublishLayerVersion".equals(operation)) {
                additional = mapper.createObjectNode().put("signatureStatus", "VALID");
            }
            String authorization = request.getHeaderString(HttpHeaders.AUTHORIZATION);
            RoutingContext context = currentRequest.getCurrent();
            cloudTrail.emitManagementEvent(new CloudTrailService.ManagementEventInput(EVENT_SOURCE,
                    catalog.eventName(operation), regions.resolveRegionFromAuth(authorization),
                    accounts.extractAccessKeyId(authorization), parameters, result, catalog.isReadOnly(operation),
                    sourceIp(context), userAgent(context), null, errorCode, errorMessage, false, null, additional,
                    null));
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
     * The record of a call IAM enforcement refused with {@code refusal} before Lambda ran it, with
     * {@code "requestParameters": null} as the 2024 records of refused Lambda calls show and the code and
     * message the refusal answered with; null for a call that is not a management event.
     */
    @Override
    public CloudTrailService.ManagementEventInput refused(String operation, String accessKeyId, String region,
                                                          RoutingContext routingContext, Response refusal) {
        CloudTrailEventCatalog catalog = CloudTrailEventCatalog.of(SERVICE);
        if (!catalog.isManagementEvent(operation)) {
            return null;
        }
        return new CloudTrailService.ManagementEventInput(EVENT_SOURCE, catalog.eventName(operation), region,
                accessKeyId, null, null, catalog.isReadOnly(operation), sourceIp(routingContext),
                userAgent(routingContext), null, REFUSED, refusalMessage(refusal));
    }

    /**
     * {@code parameters} with what a record of {@code operation} adds to the request's members:
     * UpdateFunctionCode's function ARN, {@code fullyQualifiedArn} and default {@code dryRun}, read from the
     * function's ARN in {@code answer}, and CreateFunction's and UpdateFunctionConfiguration's environment.
     */
    private ObjectNode requestParameters(String operation, ObjectNode parameters, JsonNode answer) {
        ObjectNode read = parameters == null ? mapper.createObjectNode() : parameters;
        if (ENVIRONMENT_REQUESTS.contains(operation) && !read.has("environment")) {
            read.putObject("environment");
        }
        if ("UpdateFunctionCode".equals(operation)) {
            String[] arn = answer == null ? new String[0] : answer.path("FunctionArn").asText("").split(":");
            if (arn.length >= 7) {
                String unqualified = String.join(":", arn[0], arn[1], arn[2], arn[3], arn[4], arn[5], arn[6]);
                ObjectNode qualified = read.putObject("fullyQualifiedArn");
                qualified.putObject("arnPrefix").put("partition", arn[1]).put("region", arn[3]).put("account", arn[4]);
                qualified.putObject("relativeId").put("functionName", arn[6]);
                qualified.putObject("functionQualifier");
                read.put("functionName", unqualified);
            }
            if (!read.has("dryRun")) {
                read.put("dryRun", false);
            }
        }
        return read.isEmpty() ? null : read;
    }

    /** The JSON a controller answered with, whatever form its entity takes; null when it answered nothing. */
    private JsonNode answer(Object entity) {
        if (entity == null) {
            return null;
        }
        if (entity instanceof AwsErrorResponse error) {
            return mapper.createObjectNode().put("__type", error.type()).put("message", error.message());
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

    /** Whether a request is signed for Lambda, whose routes another service's requests never take. */
    private static boolean signedForLambda(String authorization) {
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
