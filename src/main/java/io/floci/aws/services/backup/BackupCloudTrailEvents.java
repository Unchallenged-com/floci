package io.floci.aws.services.backup;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AccountResolver;
import io.floci.aws.core.common.AwsErrorResponse;
import io.floci.aws.core.common.IamConditionContextResolver;
import io.floci.aws.core.common.RegionResolver;
import io.floci.aws.core.common.RequestSourceAddress;
import io.floci.aws.core.common.ServicePrincipals;
import io.floci.aws.core.common.SharedTagsController;
import io.floci.aws.services.cloudtrail.CloudTrailEventCatalog;
import io.floci.aws.services.cloudtrail.CloudTrailService;
import io.floci.aws.services.cloudtrail.CloudTrailShapes;
import io.floci.aws.services.cloudtrail.ManagementEventSource;
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
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Records AWS Backup's API calls as CloudTrail management events: "CloudTrail captures all API calls for
 * AWS Backup as events" (https://docs.aws.amazon.com/aws-backup/latest/devguide/logging-using-cloudtrail.html).
 * Which calls, and which are read-only, are the vendored {@code aws/backup-cloudtrail-events.json}
 * ({@link CloudTrailEventCatalog}); each is recorded under its own name, as the guide's examples record
 * {@code StartBackupJob} and {@code DeleteRecoveryPoint}.
 *
 * <p>AWS Backup's API is REST-JSON, so a call is told by the controller method that serves it, and its record
 * is written here, around that method:
 * <ul>
 *   <li>{@code requestParameters} are the members the call carries in its path, its query and its body, each
 *   with a lower first letter and typed as botocore's AWS Backup model types it, as the guide's examples write
 *   them ({@code "backupVaultName"}, {@code "recoveryPointArn"}, {@code "startWindowMinutes": 60}), without the
 *   members the model marks sensitive (the tags).</li>
 *   <li>{@code responseElements} is the call's answer in the same form, with timestamps written as the guide's
 *   StartBackupJob example writes its {@code creationDate} ({@code "Jan 10, 2019 1:45:24 PM"}); null for a
 *   read-only call, a call that answers nothing (the guide's DeleteRecoveryPoint example) and a failed one.</li>
 *   <li>A failed call keeps its members and is recorded under its error's type
 *   ({@code ResourceNotFoundException}).</li>
 *   <li>A call IAM enforcement refuses never reaches the controller: it is recorded by {@link #refused}, as
 *   {@code AccessDenied} with {@code "requestParameters": null}, as the other REST-JSON services record a
 *   refusal.</li>
 * </ul>
 *
 * <p>The tag routes are the shared tags controller's: a call there is AWS Backup's when it is signed for it.
 * The events AWS Backup logs on its own ({@code AwsServiceEvent}, such as {@code BackupJobCompleted}) are not
 * API calls and are not recorded here.
 */
@Provider
@Priority(Priorities.USER + 100)
public class BackupCloudTrailEvents implements ContainerRequestFilter, ContainerResponseFilter, ManagementEventSource {

    private static final Logger LOG = Logger.getLogger(BackupCloudTrailEvents.class);
    private static final String SERVICE = "backup";
    private static final String EVENT_SOURCE = ServicePrincipals.of(SERVICE);
    private static final String CALL = BackupCloudTrailEvents.class.getName() + ".call";
    /** The guide's StartBackupJob example: {@code "creationDate": "Jan 10, 2019 1:45:24 PM"}. */
    private static final CloudTrailShapes.JsonStyle RESULT_STYLE = new CloudTrailShapes.JsonStyle(false,
            DateTimeFormatter.ofPattern("MMM d, yyyy h:mm:ss a", Locale.US).withZone(ZoneOffset.UTC));
    /** The shared tag routes AWS Backup's model gives: {@code GET /tags/{resourceArn}/}, {@code POST /tags/{resourceArn}}. */
    private static final Map<String, String> TAG_OPERATIONS = Map.of("listTags", "ListTags",
            "tagResourcePost", "TagResource");

    private final CloudTrailService cloudTrail;
    private final AccountResolver accounts;
    private final RegionResolver regions;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;
    private final ResourceInfo resourceInfo;

    @Inject
    public BackupCloudTrailEvents(CloudTrailService cloudTrail, AccountResolver accounts, RegionResolver regions,
                                  CurrentVertxRequest currentRequest, ObjectMapper mapper,
                                  @Context ResourceInfo resourceInfo) {
        this.cloudTrail = cloudTrail;
        this.accounts = accounts;
        this.regions = regions;
        this.currentRequest = currentRequest;
        this.mapper = mapper;
        this.resourceInfo = resourceInfo;
    }

    /** An AWS Backup call a trail records, as its request carried it. */
    private record Call(String operation, Map<String, String> labels, MultivaluedMap<String, String> query,
                        JsonNode body) {
    }

    /** Notes the call a request makes, with its members, before its controller reads them. */
    @Override
    public void filter(ContainerRequestContext request) {
        if (!signedForBackup(request.getHeaderString(HttpHeaders.AUTHORIZATION))) {
            return;
        }
        try {
            String operation = operation();
            if (!CloudTrailEventCatalog.of(SERVICE).isManagementEvent(operation)) {
                return;
            }
            byte[] body = IamConditionContextResolver.bufferEntity(request);
            request.setProperty(CALL, new Call(operation, labels(request), request.getUriInfo().getQueryParameters(),
                    json(body)));
        } catch (RuntimeException e) {
            // The call is served either way; a record that could not be prepared is logged, not raised.
            LOG.warnv(e, "Failed to read the AWS Backup call for CloudTrail");
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
            boolean readOnly = catalog.isReadOnly(operation);
            JsonNode answer = answer(response.getEntity());
            String errorCode = null;
            String errorMessage = null;
            if (response.getStatus() >= 400) {
                errorCode = answer == null ? null : answer.path("__type").asText(null);
                errorMessage = answer == null ? null : answer.path("message").asText(null);
            }
            ObjectNode parameters = shapes.requestParameters(operation, call.labels(), call.query(), call.body(),
                    CloudTrailShapes.JsonStyle.AS_SENT);
            ObjectNode result = errorCode == null && !readOnly ? shapes.result(operation, answer, RESULT_STYLE) : null;
            String authorization = request.getHeaderString(HttpHeaders.AUTHORIZATION);
            RoutingContext context = currentRequest.getCurrent();
            cloudTrail.emitManagementEvent(new CloudTrailService.ManagementEventInput(EVENT_SOURCE,
                    catalog.eventName(operation), regions.resolveRegionFromAuth(authorization),
                    accounts.extractAccessKeyId(authorization), parameters, result, readOnly, sourceIp(context),
                    userAgent(context), null, errorCode, errorMessage));
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
     * The record of a call IAM enforcement refused with {@code refusal} before AWS Backup ran it, with
     * {@code "requestParameters": null} and the code and message the refusal answered with; null for a call
     * that is not a management event.
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
     * The operation the matched controller method serves: a {@link BackupController} method is named after its
     * operation, and the shared tags controller serves AWS Backup's ListTags and TagResource routes.
     */
    private String operation() {
        Method method = resourceInfo == null ? null : resourceInfo.getResourceMethod();
        if (method == null) {
            return null;
        }
        Class<?> controller = resourceInfo.getResourceClass();
        if (BackupController.class.equals(controller)) {
            String name = method.getName();
            return Character.toUpperCase(name.charAt(0)) + name.substring(1);
        }
        return SharedTagsController.class.equals(controller) ? TAG_OPERATIONS.get(method.getName()) : null;
    }

    /**
     * The request's path parameters by the names AWS Backup's model gives them, which its controller uses, and
     * the shared tags controller's {@code arn} as the model's {@code resourceArn}, without ListTags' trailing slash.
     */
    private static Map<String, String> labels(ContainerRequestContext request) {
        Map<String, String> labels = new HashMap<>();
        for (Map.Entry<String, List<String>> parameter : request.getUriInfo().getPathParameters().entrySet()) {
            if (!parameter.getValue().isEmpty()) {
                labels.put(parameter.getKey(), parameter.getValue().getFirst());
            }
        }
        String arn = labels.remove("arn");
        if (arn != null) {
            labels.put("resourceArn", arn.endsWith("/") ? arn.substring(0, arn.length() - 1) : arn);
        }
        return labels;
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

    /** Whether a request is signed for AWS Backup, which the shared tag routes serve for other services too. */
    private static boolean signedForBackup(String authorization) {
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
