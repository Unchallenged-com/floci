package io.floci.aws.services.ec2instanceconnect;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AwsErrorResponse;
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
 * Records EC2 Instance Connect's calls as CloudTrail management events: the event history shows "the
 * events that correspond to the SendSSHPublicKey API calls" under the event source
 * {@code ec2-instance-connect.amazonaws.com}, whose {@code requestParameters} carry "the destination
 * instance ID, OS username, and public key that were used to make the SSH connection"
 * (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitor-with-cloudtrail.html#ec2-instance-connect-cloudtrail).
 * Which calls those are is the vendored {@code aws/ec2-instance-connect-cloudtrail-events.json}
 * ({@link CloudTrailEventCatalog}): {@code SendSSHPublicKey} and {@code SendSerialConsoleSSHPublicKey},
 * neither read-only.
 *
 * <p>A call is recorded whether it succeeds, fails, or is refused by IAM enforcement, a trail or not,
 * since event history keeps every management event. The record follows 2024 records of both calls:
 * {@code requestParameters} are the request's members with a lower first letter, as botocore's model
 * names them ({@code "instanceId"}, {@code "instanceOSUser"}, {@code "sSHPublicKey"} with the key as
 * sent), and {@code responseElements} the answer's ({@code "requestId"}, {@code "success": true}),
 * whose {@code requestId} is the record's {@code requestID}. The guide's own example, from 2018, names
 * the members otherwise ({@code "osUser"}, {@code "SSHKey"}); records since 2024 do not. An error is
 * recorded under the {@code __type} the call answers with ({@code EC2InstanceNotFoundException}), a
 * refusal as {@link #REFUSED} with {@code "requestParameters": null}.
 *
 * <p>Not recorded: {@code OpenTunnel}, the connection an EC2 Instance Connect Endpoint logs, and the
 * {@code monitorMode} a serial console record carries, which the model does not.
 */
@ApplicationScoped
public class InstanceConnectCloudTrailEvents implements ManagementEventSource {

    private static final Logger LOG = Logger.getLogger(InstanceConnectCloudTrailEvents.class);
    private static final String SERVICE = "ec2-instance-connect";
    private static final String EVENT_SOURCE = ServicePrincipals.of(SERVICE);

    private final CloudTrailService cloudTrail;
    private final RequestContext requestContext;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;

    @Inject
    public InstanceConnectCloudTrailEvents(CloudTrailService cloudTrail, RequestContext requestContext,
                                           CurrentVertxRequest currentRequest, ObjectMapper mapper) {
        this.cloudTrail = cloudTrail;
        this.requestContext = requestContext;
        this.currentRequest = currentRequest;
        this.mapper = mapper;
    }

    /**
     * Records the call {@code response} answered, or that failed with {@code error} when it is set, as the
     * caller the request was signed by.
     */
    void record(String action, JsonNode request, String region, Response response, AwsException error) {
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
                } else if (response.getStatus() < 400 && response.getEntity() != null) {
                    result = shapes.result(action, mapper.valueToTree(response.getEntity()));
                }
            }
            String requestId = result == null ? null : result.path("requestId").asText(null);
            HttpServerRequest caller = request(currentRequest.getCurrent());
            cloudTrail.emitManagementEvent(new CloudTrailService.ManagementEventInput(EVENT_SOURCE, action, region,
                    requestContext.getAccessKeyId(), shapes.requestParameters(action, request), result,
                    catalog.isReadOnly(action), sourceIp(caller), userAgent(caller), requestId, errorCode,
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
     * The record of a call IAM enforcement refused with {@code refusal} before EC2 Instance Connect ran it,
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
