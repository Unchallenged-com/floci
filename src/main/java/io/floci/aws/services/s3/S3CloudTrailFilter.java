package io.floci.aws.services.s3;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AccountResolver;
import io.floci.aws.core.common.AwsEndpoints;
import io.floci.aws.core.common.AwsException;
import io.floci.aws.core.common.AwsRegions;
import io.floci.aws.core.common.IamEnforcementFilter;
import io.floci.aws.core.common.RegionResolver;
import io.floci.aws.core.common.RequestContext;
import io.floci.aws.core.common.RequestSourceAddress;
import io.floci.aws.core.common.ServicePrincipals;
import io.floci.aws.core.common.XmlParser;
import io.floci.aws.services.cloudtrail.CloudTrailService;
import io.floci.aws.services.s3.model.S3Object;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Records the S3 requests {@code S3Controller} does not record itself as the CloudTrail events
 * {@link S3CloudTrailEvents} names: the remaining object-level data events, {@code DeleteObjects}
 * with a {@code DeleteObject} for each object it deleted, {@code ListObjectVersions},
 * {@code HeadBucket}, and the bucket-level management events. A request IAM enforcement refused is
 * recorded here too, unless the refusal was recorded when it was made
 * ({@link #RECORDED_PROPERTY}).
 */
@Provider
public class S3CloudTrailFilter implements ContainerRequestFilter, ContainerResponseFilter {

    /** Set on a request whose CloudTrail event was already recorded, such as an IAM refusal. */
    public static final String RECORDED_PROPERTY = S3CloudTrailFilter.class.getName() + ".recorded";
    /** Set on a request IAM enforcement refused, to the refusal its record carries as {@code errorMessage}. */
    public static final String DENIAL_MESSAGE_PROPERTY = S3CloudTrailFilter.class.getName() + ".denialMessage";

    private static final Logger LOG = Logger.getLogger(S3CloudTrailFilter.class);
    private static final String BODY_PROPERTY = S3CloudTrailFilter.class.getName() + ".body";
    private static final String EVENT_SOURCE = ServicePrincipals.of("s3");
    /** A bucket configuration is small; a larger body is not held to be recorded. */
    private static final int MAX_RECORDED_BODY = 64 * 1024;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final CloudTrailService cloudTrail;
    private final AccountResolver accounts;
    private final RequestContext requestContext;
    private final RegionResolver regionResolver;
    private final CurrentVertxRequest currentRequest;
    private final ResourceInfo resourceInfo;
    private final S3Service s3Service;

    @Inject
    public S3CloudTrailFilter(CloudTrailService cloudTrail, AccountResolver accounts, RequestContext requestContext,
                              RegionResolver regionResolver, CurrentVertxRequest currentRequest,
                              @Context ResourceInfo resourceInfo, S3Service s3Service) {
        this.cloudTrail = cloudTrail;
        this.accounts = accounts;
        this.requestContext = requestContext;
        this.regionResolver = regionResolver;
        this.currentRequest = currentRequest;
        this.resourceInfo = resourceInfo;
        this.s3Service = s3Service;
    }

    /** Holds a bucket configuration's body, which the resource method consumes, so its record can carry it. */
    @Override
    public void filter(ContainerRequestContext request) throws IOException {
        if (!S3SignatureFilterScope.routedToS3(resourceInfo) || !cloudTrail.hasTrails()
                || !"PUT".equalsIgnoreCase(request.getMethod())) {
            return;
        }
        S3CloudTrailEvents.Event event = event(request);
        if (event == null || event.category() != S3CloudTrailEvents.Category.MANAGEMENT || event.subresource() == null) {
            return;
        }
        InputStream entity = request.getEntityStream();
        byte[] body = entity.readNBytes(MAX_RECORDED_BODY + 1);
        byte[] rest = entity.readAllBytes();
        byte[] whole = new byte[body.length + rest.length];
        System.arraycopy(body, 0, whole, 0, body.length);
        System.arraycopy(rest, 0, whole, body.length, rest.length);
        request.setEntityStream(new ByteArrayInputStream(whole));
        if (whole.length <= MAX_RECORDED_BODY) {
            request.setProperty(BODY_PROPERTY, whole);
        }
    }

    @Override
    public void filter(ContainerRequestContext request, ContainerResponseContext response) {
        if (!S3SignatureFilterScope.routedToS3(resourceInfo) || !cloudTrail.hasTrails()
                || request.getProperty(RECORDED_PROPERTY) != null) {
            return;
        }
        try {
            S3CloudTrailEvents.Event event = event(request);
            if (event == null || S3CloudTrailEvents.RECORDED_BY_CONTROLLER.contains(event.name())
                    || isServiceRootCompanion(request)) {
                return;
            }
            record(request, response, event);
        } catch (RuntimeException e) {
            // The response is already decided; a record that could not be written is logged, not raised.
            LOG.warnv(e, "CloudTrail: could not record S3 {0} {1}", request.getMethod(),
                    request.getUriInfo().getPath());
        }
    }

    private static S3CloudTrailEvents.Event event(ContainerRequestContext request) {
        MultivaluedMap<String, String> path = request.getUriInfo().getPathParameters();
        String copySource = request.getHeaderString("x-amz-copy-source");
        return S3CloudTrailEvents.of(request.getMethod(), path.getFirst("bucket"), path.getFirst("key"),
                request.getUriInfo().getQueryParameters().keySet(), copySource != null && !copySource.isEmpty());
    }

    /** The service root also answers SNS's subscription links and Floci's own page, which are no S3 calls. */
    private static boolean isServiceRootCompanion(ContainerRequestContext request) {
        MultivaluedMap<String, String> query = request.getUriInfo().getQueryParameters();
        return request.getUriInfo().getPathParameters().getFirst("bucket") == null
                && (request.getHeaderString("X-Amz-Target") != null || query.containsKey("Action")
                    || request.getHeaderString("Authorization") == null && !query.containsKey("X-Amz-Credential"));
    }

    private void record(ContainerRequestContext request, ContainerResponseContext response,
                        S3CloudTrailEvents.Event event) {
        String bucket = request.getUriInfo().getPathParameters().getFirst("bucket");
        String key = request.getUriInfo().getPathParameters().getFirst("key");
        String authorization = IamEnforcementFilter.requestAuthorization(request.getHeaderString("Authorization"),
                request.getUriInfo().getQueryParameters());
        String accessKeyId = accounts.extractS3AccessKeyId(authorization);
        String region = requestContext.getRegion() != null ? requestContext.getRegion()
                : regionResolver.getDefaultRegion();
        RoutingContext routingContext = currentRequest.getCurrent();
        HttpServerRequest http = routingContext == null ? null : routingContext.request();
        String sourceIp = http == null ? null : RequestSourceAddress.of(http);
        String userAgent = request.getHeaderString("User-Agent");
        String entity = entityText(response.getEntity());
        String errorCode = response.getStatus() >= 400 ? errorCode(entity, response.getStatus()) : null;
        if (response.getStatus() >= 400 && errorCode == null) {
            // A failure without its error, such as a HEAD's, would read as a success.
            return;
        }
        String errorMessage = request.getProperty(DENIAL_MESSAGE_PROPERTY) instanceof String denial ? denial
                : errorCode == null || entity == null ? null : XmlParser.extractFirst(entity, "Message", null);
        Map<String, String> query = S3CloudTrailEvents.recordedQueryParameters(
                request.getUriInfo().getQueryParameters());
        long bytesIn = Math.max(0L, request.getLength());
        long bytesOut = Math.max(0L, response.getLength());

        if (event.category() == S3CloudTrailEvents.Category.MANAGEMENT) {
            ObjectNode parameters = MAPPER.createObjectNode();
            if (bucket != null) {
                parameters.put("bucketName", bucket);
            }
            parameters.put("Host", bucket == null ? "s3." + AwsRegions.dnsSuffixFor(region)
                    : AwsEndpoints.s3Host(bucket, region));
            query.forEach(parameters::put);
            if (request.getProperty(BODY_PROPERTY) instanceof byte[] body) {
                ObjectNode read = "policy".equals(event.subresource())
                        ? S3CloudTrailEvents.policyBody(body) : S3CloudTrailEvents.xmlBody(body);
                if (read != null) {
                    parameters.setAll(read);
                }
            }
            ArrayNode resources = null;
            if (bucket != null && !"CreateBucket".equals(event.name())) {
                resources = MAPPER.createArrayNode();
                resources.addObject()
                        .put("accountId", regionResolver.getAccountId())
                        .put("type", "AWS::S3::Bucket")
                        .put("ARN", S3ResourceArns.bucket(AwsRegions.partitionFor(region), bucket));
            }
            cloudTrail.emitManagementEvent(new CloudTrailService.ManagementEventInput(EVENT_SOURCE, event.name(),
                    region, accessKeyId, parameters, null, event.readOnly(), sourceIp, userAgent,
                    response.getHeaderString("x-amz-request-id"), errorCode, errorMessage, false, null,
                    cloudTrail.s3AdditionalEventData(bytesIn, bytesOut), resources));
            return;
        }
        cloudTrail.emitS3DataEvent(dataEvent(region, event.name(), bucket, key, accessKeyId, sourceIp, userAgent,
                errorCode, errorMessage).queryParameters(query).bytesIn(bytesIn).bytesOut(bytesOut)
                .objectRetentionInfo(errorCode == null ? objectRetentionInfo(event.name(), bucket, key, query) : null)
                .build());
        if ("DeleteObjects".equals(event.name()) && errorCode == null && entity != null) {
            // "the event record for an Amazon S3 DeleteObjects data event includes both the DeleteObjects event
            // and a DeleteObject event for each object deleted as part of that operation"
            for (String deleted : deletedKeys(entity)) {
                cloudTrail.emitS3DataEvent(dataEvent(region, "DeleteObject", bucket, deleted, accessKeyId, sourceIp,
                        userAgent, null, null).build());
            }
        }
    }

    /**
     * The retention and legal hold an Object Lock call read or left, as S3 records them in
     * {@code additionalEventData.objectRetentionInfo}: a retention call carries the object's
     * {@code retentionInfo}, a legal hold call its {@code legalHoldInfo}, and a retention it sets also
     * the legal hold the object is under, times in epoch milliseconds. Null for any other event.
     */
    private ObjectNode objectRetentionInfo(String eventName, String bucket, String key, Map<String, String> query) {
        boolean retention = "PutObjectLockRetention".equals(eventName) || "GetObjectLockRetention".equals(eventName);
        boolean legalHold = "PutObjectLockLegalHold".equals(eventName) || "GetObjectLockLegalHold".equals(eventName);
        if (!retention && !legalHold) {
            return null;
        }
        S3Object object;
        try {
            object = s3Service.getObjectLockState(bucket, key, query.get("versionId"));
        } catch (AwsException e) {
            LOG.debugv("CloudTrail: no Object Lock state to record for {0}/{1}: {2}", bucket, key, e.getMessage());
            return null;
        }
        ObjectNode info = MAPPER.createObjectNode();
        if (retention && object.getObjectLockMode() != null) {
            ObjectNode retentionInfo = info.putObject("retentionInfo");
            putTime(retentionInfo, "lastModifiedTime", object.getRetentionModifiedAt());
            retentionInfo.put("retainUntilMode", object.getObjectLockMode());
            putTime(retentionInfo, "retainUntilTime", object.getRetainUntilDate());
        }
        boolean recordsLegalHold = legalHold || "PutObjectLockRetention".equals(eventName);
        if (recordsLegalHold && object.getLegalHoldStatus() != null) {
            ObjectNode legalHoldInfo = info.putObject("legalHoldInfo");
            legalHoldInfo.put("isUnderLegalHold", "ON".equals(object.getLegalHoldStatus()));
            putTime(legalHoldInfo, "lastModifiedTime", object.getLegalHoldModifiedAt());
        }
        return info.isEmpty() ? null : info;
    }

    private static void putTime(ObjectNode node, String name, Instant time) {
        if (time != null) {
            node.put(name, time.toEpochMilli());
        }
    }

    private static CloudTrailService.S3EventInput.Builder dataEvent(String region, String name, String bucket,
                                                                    String key, String accessKeyId, String sourceIp,
                                                                    String userAgent, String errorCode,
                                                                    String errorMessage) {
        return CloudTrailService.S3EventInput.builder()
                .region(region)
                .eventName(name)
                .bucketName(bucket)
                .key(key)
                .accessKeyId(accessKeyId)
                .sourceIp(sourceIp)
                .userAgent(userAgent)
                .errorCode(errorCode)
                .errorMessage(errorMessage)
                .eventTimeMillis(System.currentTimeMillis());
    }

    private static List<String> deletedKeys(String entity) {
        return XmlParser.extractGroups(entity, "Deleted").stream()
                .map(deleted -> deleted.get("Key"))
                .filter(key -> key != null && !key.isEmpty())
                .toList();
    }

    /** The error S3 answered with; a response without a body, as to a HEAD, names none. */
    private static String errorCode(String entity, int status) {
        String code = entity == null ? null : XmlParser.extractFirst(entity, "Code", null);
        if (code != null) {
            return code;
        }
        LOG.debugv("CloudTrail: S3 answered {0} without an error code", status);
        return null;
    }

    private static String entityText(Object entity) {
        if (entity instanceof String text) {
            return text;
        }
        if (entity instanceof byte[] bytes) {
            return new String(bytes, StandardCharsets.UTF_8);
        }
        return null;
    }
}
