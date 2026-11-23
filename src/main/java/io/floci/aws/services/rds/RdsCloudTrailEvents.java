package io.floci.aws.services.rds;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AccountResolver;
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
 * Records RDS's API calls as CloudTrail management events: "All Amazon RDS actions are logged by CloudTrail"
 * (https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/logging-using-cloudtrail.html). Which calls, and which
 * are read-only, is the vendored {@code aws/rds-cloudtrail-events.json} ({@link CloudTrailEventCatalog}). Neptune
 * and DocumentDB calls are recorded the same way, as their guides say they are "logged as calls made to the
 * Amazon RDS API" (https://docs.aws.amazon.com/neptune/latest/userguide/cloudtrail.html,
 * https://docs.aws.amazon.com/documentdb/latest/developerguide/logging-with-cloudtrail.html).
 *
 * <p>A call is recorded under its own name, whether it succeeds, fails or is refused, as records of
 * {@code CreateDBInstance}, {@code ModifyDBInstance}, {@code ModifyDBCluster}, {@code DeleteDBInstance} and
 * {@code ModifyDBSnapshotAttribute} since 2024 write it:
 * <ul>
 *   <li>{@code eventSource} {@code rds.amazonaws.com}, and {@code requestParameters} the request's members named
 *   with a lower first letter and typed as botocore's RDS model types them, a list as a JSON array
 *   ({@code "valuesToAdd": ["123456789012"]}, {@code "allocatedStorage": 20}).</li>
 *   <li>{@code responseElements} the answer in the same form, its one structure written as its own members
 *   ({@code "dBInstanceArn"} at the top, not under {@code "dBInstance"}); null for a read-only call and a failed
 *   one.</li>
 *   <li>A member the model marks sensitive, the master user password above all, is written
 *   {@value #SENSITIVE} in the request and in the answer's {@code pendingModifiedValues} alike.</li>
 *   <li>A failed call keeps its members, under the name of the error shape botocore's model gives the code it
 *   answered ({@code DBInstanceNotFound} as {@code DBInstanceNotFoundFault}), as records since 2024 name a failed
 *   call's error after its shape; a code the model does not declare is kept as answered. One IAM enforcement
 *   refuses is recorded as {@code AccessDenied} with {@code "requestParameters": null}.</li>
 * </ul>
 */
@ApplicationScoped
public class RdsCloudTrailEvents implements ManagementEventSource {

    /** The Query scopes whose calls are RDS API calls: RDS's own, Neptune's and DocumentDB's. */
    public static final Set<String> SCOPES = Set.of("rds", "neptune", "docdb");

    private static final Logger LOG = Logger.getLogger(RdsCloudTrailEvents.class);
    /** The IAM service prefix, which names the events and shapes files and the credential scope RDS signs with. */
    private static final String SERVICE = "rds";
    private static final String EVENT_SOURCE = ServicePrincipals.of(SERVICE);
    /** What a 2024 record writes for {@code masterUserPassword}, in the request and in the answer. */
    static final String SENSITIVE = "HIDDEN_DUE_TO_SECURITY_REASONS";
    private static final CloudTrailShapes.QueryStyle STYLE = new CloudTrailShapes.QueryStyle(SENSITIVE, true);

    private final CloudTrailService cloudTrail;
    private final AccountResolver accounts;
    private final CurrentVertxRequest currentRequest;

    @Inject
    public RdsCloudTrailEvents(CloudTrailService cloudTrail, AccountResolver accounts,
                               CurrentVertxRequest currentRequest) {
        this.cloudTrail = cloudTrail;
        this.accounts = accounts;
        this.currentRequest = currentRequest;
    }

    /**
     * Runs {@code call}, the Query call {@code action} carrying {@code params} signed with {@code authorization},
     * and records it.
     */
    public Response recorded(String action, MultivaluedMap<String, String> params, String region,
                             String authorization, Supplier<Response> call) {
        Response response;
        try {
            response = call.get();
        } catch (AwsException e) {
            record(action, params, null, region, authorization, e.getErrorCode(), e.getMessage());
            throw e;
        }
        String xml = response.getEntity() instanceof String text ? text : null;
        if (response.getStatus() >= 400) {
            XmlParser.XmlElement error = xml == null ? null : XmlParser.extractElementTree(xml, "Error");
            record(action, params, null, region, authorization,
                    error == null || error.child("Code") == null ? null : error.child("Code").text(),
                    error == null || error.child("Message") == null ? null : error.child("Message").text());
        } else {
            record(action, params, xml, region, authorization, null, null);
        }
        return response;
    }

    @Override
    public String credentialScope() {
        return SERVICE;
    }

    /**
     * The record of a call IAM enforcement refused with {@code refusal} before RDS ran it, with
     * {@code "requestParameters": null} and the code and message the refusal answered with; null for a call
     * that is not a management event.
     */
    @Override
    public CloudTrailService.ManagementEventInput refused(String operation, String accessKeyId, String region,
                                                          RoutingContext routingContext, Response refusal) {
        if (!CloudTrailEventCatalog.of(SERVICE).isManagementEvent(operation)) {
            return null;
        }
        return event(operation, null, null, accessKeyId, region, routingContext, REFUSED, refusalMessage(refusal));
    }

    private void record(String action, MultivaluedMap<String, String> params, String xml, String region,
                        String authorization, String errorCode, String errorMessage) {
        CloudTrailEventCatalog catalog = CloudTrailEventCatalog.of(SERVICE);
        if (!catalog.isManagementEvent(action)) {
            return;
        }
        try {
            CloudTrailShapes shapes = CloudTrailShapes.of(SERVICE);
            ObjectNode answered = errorCode == null && xml != null && !catalog.isReadOnly(action)
                    ? shapes.result(action, xml, STYLE) : null;
            cloudTrail.emitManagementEvent(event(action, shapes.requestParameters(action, params, STYLE), answered,
                    accounts.extractAccessKeyId(authorization), region, currentRequest.getCurrent(),
                    shapes.recordedErrorCode(errorCode), errorMessage));
        } catch (RuntimeException e) {
            // The call is answered either way; a record that could not be written is logged, not raised.
            LOG.warnv(e, "Failed to record CloudTrail call {0}", action);
        }
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
