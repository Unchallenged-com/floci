package io.floci.aws.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AccountResolver;
import io.floci.aws.core.common.AwsArnUtils;
import io.floci.aws.core.common.RegionResolver;
import io.floci.aws.core.common.ServicePrincipals;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;

import java.util.List;
import java.util.Map;

/**
 * Records CloudTrail's own API calls as management events, as CloudTrail records any service's:
 * "Setting up logging (for example, AWS CloudTrail CreateTrail API operations)" is the guide's own
 * example of a management event
 * (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-events.html). The record
 * follows that page's {@code StartLogging} event and the log file examples' failed {@code UpdateTrail}
 * (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html):
 * {@code eventSource} {@code cloudtrail.amazonaws.com}, {@code requestParameters} the request's members
 * with a lower first letter ({@code {"name": "myTrail"}}), {@code "responseElements": null} for a call
 * that answers nothing or fails, and the error's own code ({@code TrailNotFoundException}) and message.
 * A call that answers something records it the same way, and a read-only call
 * ({@code Describe*}, {@code Get*}, {@code List*}, {@code Lookup*}) has its result redacted, as
 * "When logging a read-only event, CloudTrail redacts the responseElements information".
 */
@ApplicationScoped
public class CloudTrailApiEvents {

    private static final Logger LOG = Logger.getLogger(CloudTrailApiEvents.class);
    private static final String EVENT_SOURCE = ServicePrincipals.of("cloudtrail");
    private static final List<String> READ_ONLY_PREFIXES = List.of("Describe", "Get", "List", "Lookup");

    private final CloudTrailService cloudTrail;
    private final AccountResolver accounts;
    private final RegionResolver regionResolver;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;

    @Inject
    public CloudTrailApiEvents(CloudTrailService cloudTrail, AccountResolver accounts, RegionResolver regionResolver,
                               CurrentVertxRequest currentRequest, ObjectMapper mapper) {
        this.cloudTrail = cloudTrail;
        this.accounts = accounts;
        this.regionResolver = regionResolver;
        this.currentRequest = currentRequest;
        this.mapper = mapper;
    }

    /**
     * Records the call made at {@code occurredAt} (epoch milliseconds) that {@code response} answered,
     * or that failed with {@code errorCode} when it is set.
     */
    void record(String action, JsonNode request, String region, String authorization, long occurredAt,
                Response response, String errorCode, String errorMessage) {
        try {
            ObjectNode result = errorCode == null && !isReadOnly(action) && response != null
                    && response.getEntity() != null ? named(mapper.valueToTree(response.getEntity())) : null;
            HttpServerRequest http = request(currentRequest.getCurrent());
            cloudTrail.emitManagementEvent(new CloudTrailService.ManagementEventInput(EVENT_SOURCE, action, region,
                    accounts.extractAccessKeyId(authorization), named(request), result, isReadOnly(action),
                    sourceIp(http), userAgent(http), null, errorCode, errorMessage, null,
                    errorCode == null ? resources(action, request, region) : null), occurredAt);
        } catch (RuntimeException e) {
            // The call is answered either way; a record that could not be written is logged, not raised.
            LOG.warnv(e, "Failed to record CloudTrail call {0}", action);
        }
    }

    /**
     * The record of a call IAM enforcement refused before CloudTrail ran it, with
     * {@code "requestParameters": null} as AWS records an authorization refusal.
     */
    public static CloudTrailService.ManagementEventInput denied(String action, String accessKeyId, String region,
                                                                RoutingContext routingContext, String errorCode,
                                                                String errorMessage) {
        HttpServerRequest http = request(routingContext);
        return new CloudTrailService.ManagementEventInput(EVENT_SOURCE, action, region, accessKeyId, null, null,
                isReadOnly(action), sourceIp(http), userAgent(http), null, errorCode, errorMessage);
    }

    /**
     * The trail a successful {@code StopLogging} stopped, as AWS records it
     * ({@code AWS::CloudTrail::Trail}, its ARN and account); no other call's resources are known.
     */
    ArrayNode resources(String action, JsonNode request, String region) {
        String name = request == null ? null : request.path("Name").asText(null);
        if (!"StopLogging".equals(action) || name == null) {
            return null;
        }
        String accountId = regionResolver.getAccountId();
        String arn = AwsArnUtils.isArn(name) ? name
                : AwsArnUtils.Arn.of("cloudtrail", region, accountId, "trail/" + name).toString();
        ArrayNode resources = mapper.createArrayNode();
        resources.addObject().put("ARN", arn).put("accountId", AwsArnUtils.parse(arn).accountId())
                .put("type", "AWS::CloudTrail::Trail");
        return resources;
    }

    /** Whether CloudTrail records {@code action} as read-only. */
    static boolean isReadOnly(String action) {
        return READ_ONLY_PREFIXES.stream().anyMatch(action::startsWith);
    }

    /** {@code node} with every member named with a lower first letter; null when it holds none. */
    ObjectNode named(JsonNode node) {
        JsonNode named = lowerFirst(node);
        return named instanceof ObjectNode object && !object.isEmpty() ? object : null;
    }

    private JsonNode lowerFirst(JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return null;
        }
        if (node.isArray()) {
            ArrayNode array = mapper.createArrayNode();
            node.forEach(element -> array.add(lowerFirst(element)));
            return array;
        }
        if (!node.isObject()) {
            return node;
        }
        ObjectNode object = mapper.createObjectNode();
        for (Map.Entry<String, JsonNode> member : node.properties()) {
            JsonNode value = lowerFirst(member.getValue());
            if (value != null) {
                String name = member.getKey();
                object.set(name.isEmpty() ? name : Character.toLowerCase(name.charAt(0)) + name.substring(1), value);
            }
        }
        return object;
    }

    private static HttpServerRequest request(RoutingContext routingContext) {
        return routingContext == null ? null : routingContext.request();
    }

    private static String sourceIp(HttpServerRequest request) {
        return request == null || request.remoteAddress() == null ? null : request.remoteAddress().host();
    }

    private static String userAgent(HttpServerRequest request) {
        return request == null ? null : request.getHeader("User-Agent");
    }
}
