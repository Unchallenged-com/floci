package io.floci.aws.services.ssm;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AccountResolver;
import io.floci.aws.core.common.AwsArnUtils;
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

/**
 * Records Systems Manager's calls as CloudTrail management events: "Systems Manager logs all control
 * plane operations to CloudTrail as management events"
 * (https://docs.aws.amazon.com/systems-manager/latest/userguide/monitoring-cloudtrail-logs.html). Which
 * calls those are, and which of them are read-only, is the vendored {@code aws/ssm-cloudtrail-events.json}
 * ({@link CloudTrailEventCatalog}): the operations Floci serves, and AWS's Service Reference's access
 * level ({@code GetParameter}, {@code GetCommandInvocation} and the other reads are read-only).
 *
 * <p>A call is recorded whether it succeeds, fails, or is refused by IAM enforcement, a trail or not,
 * since event history keeps every management event. The record follows 2024 records of
 * {@code SendCommand}, {@code GetCommandInvocation}, {@code DescribeParameters} and {@code GetParameters}:
 * <ul>
 *   <li>{@code requestParameters} and {@code responseElements} are the request's and the result's
 *   members with a lower first letter, typed as botocore's SSM model types them
 *   ({@code "instanceIds": [...]}, {@code "withDecryption": true}, {@code "maxResults": 10}).</li>
 *   <li>A member the model marks sensitive is written {@code "HIDDEN_DUE_TO_SECURITY_REASONS"}, as a
 *   {@code SendCommand} record writes its {@code parameters} in the request and in the command it
 *   answers: the commands a {@code SendCommand} runs and the value a {@code PutParameter} stores are
 *   never recorded.</li>
 *   <li>A timestamp in the result is written as that record writes one
 *   ({@code "expiresAfter": "Aug 2, 2024, 11:08:56 AM"}).</li>
 *   <li>{@code responseElements} is null for a read-only call, so no parameter value a
 *   {@code GetParameter} decrypts reaches a record, for a call that answers nothing and for a failed
 *   one.</li>
 *   <li>A {@code GetParameters} record lists the parameters it read in {@code resources}, each by its
 *   {@code ARN} and {@code accountId}.</li>
 * </ul>
 * An error is recorded under the {@code __type} the JSON protocol answers with
 * ({@code ParameterNotFound}), a refusal as {@link #REFUSED} with {@code "requestParameters": null}.
 * The data events (CreateControlChannel, OpenControlChannel, RequestManagedInstanceRoleToken) are not
 * recorded, nor are the members a record carries that the model does not
 * ({@code SendCommand}'s {@code interactive}).
 */
@ApplicationScoped
public class SsmCloudTrailEvents implements ManagementEventSource {

    private static final Logger LOG = Logger.getLogger(SsmCloudTrailEvents.class);
    private static final String SERVICE = "ssm";
    private static final String EVENT_SOURCE = ServicePrincipals.of(SERVICE);
    /** What a record carries in place of a sensitive member, as a 2024 SendCommand record does. */
    static final String HIDDEN = "HIDDEN_DUE_TO_SECURITY_REASONS";
    private static final CloudTrailShapes.JsonStyle STYLE = new CloudTrailShapes.JsonStyle(false,
            DateTimeFormatter.ofPattern("MMM d, yyyy, h:mm:ss a", Locale.US).withZone(ZoneOffset.UTC), HIDDEN);

    private final CloudTrailService cloudTrail;
    private final AccountResolver accounts;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;

    @Inject
    public SsmCloudTrailEvents(CloudTrailService cloudTrail, AccountResolver accounts,
                               CurrentVertxRequest currentRequest, ObjectMapper mapper) {
        this.cloudTrail = cloudTrail;
        this.accounts = accounts;
        this.currentRequest = currentRequest;
        this.mapper = mapper;
    }

    /**
     * Records the call {@code response} answered, or that failed with {@code error} when it is set, as the
     * caller {@code authorization} names.
     */
    void record(String action, JsonNode request, String region, String authorization, Response response,
                AwsException error) {
        CloudTrailEventCatalog catalog = CloudTrailEventCatalog.of(SERVICE);
        if (!catalog.isManagementEvent(action)) {
            return;
        }
        try {
            CloudTrailShapes shapes = CloudTrailShapes.of(SERVICE);
            String errorCode = error == null ? null : error.jsonType();
            String errorMessage = error == null ? null : error.getMessage();
            JsonNode answered = null;
            if (error == null && response != null) {
                if (response.getEntity() instanceof AwsErrorResponse failure) {
                    errorCode = failure.type();
                    errorMessage = failure.message();
                } else if (response.getStatus() < 400 && response.getEntity() != null) {
                    answered = mapper.valueToTree(response.getEntity());
                }
            }
            ObjectNode result = answered != null && !catalog.isReadOnly(action)
                    ? shapes.result(action, answered, STYLE) : null;
            HttpServerRequest caller = request(currentRequest.getCurrent());
            cloudTrail.emitManagementEvent(new CloudTrailService.ManagementEventInput(EVENT_SOURCE, action, region,
                    accounts.extractAccessKeyId(authorization), shapes.requestParameters(action, request, STYLE),
                    result, catalog.isReadOnly(action), sourceIp(caller), userAgent(caller), null, errorCode,
                    errorMessage, false, null, null, resources(action, answered)));
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
     * The record of a call IAM enforcement refused with {@code refusal} before Systems Manager ran it,
     * with {@code "requestParameters": null} as AWS records an authorization refusal and the message the
     * refusal answered with; null for a call that is not a management event.
     */
    @Override
    public CloudTrailService.ManagementEventInput refused(String operation, String accessKeyId, String region,
                                                          RoutingContext routingContext, Response refusal) {
        CloudTrailEventCatalog catalog = CloudTrailEventCatalog.of(SERVICE);
        if (!catalog.isManagementEvent(operation)) {
            return null;
        }
        HttpServerRequest caller = request(routingContext);
        return new CloudTrailService.ManagementEventInput(EVENT_SOURCE, operation, region, accessKeyId, null, null,
                catalog.isReadOnly(operation), sourceIp(caller), userAgent(caller), null, REFUSED,
                refusalMessage(refusal));
    }

    /** The parameters a GetParameters call read, as its record lists them; null for any other call. */
    private ArrayNode resources(String action, JsonNode answered) {
        if (!"GetParameters".equals(action) || answered == null) {
            return null;
        }
        ArrayNode resources = mapper.createArrayNode();
        for (JsonNode parameter : answered.path("Parameters")) {
            String arn = parameter.path("ARN").asText(null);
            if (arn != null) {
                resources.addObject().put("ARN", arn).put("accountId", AwsArnUtils.accountOrDefault(arn, ""));
            }
        }
        return resources;
    }

    private static HttpServerRequest request(RoutingContext context) {
        return context == null ? null : context.request();
    }

    private static String sourceIp(HttpServerRequest request) {
        return request == null ? null : RequestSourceAddress.of(request);
    }

    private static String userAgent(HttpServerRequest request) {
        return request == null ? null : request.getHeader("User-Agent");
    }
}
