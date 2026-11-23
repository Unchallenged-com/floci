package io.floci.aws.services.kms;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AwsArnUtils;
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

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Records KMS's calls as CloudTrail management events: "CloudTrail logs all AWS KMS operations,
 * including read-only operations, ... operations that manage KMS keys, ... and cryptographic
 * operations" (https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html).
 * Which are read-only is the vendored {@code aws/kms-cloudtrail-events.json}
 * ({@link CloudTrailEventCatalog}): the reads AWS's Service Reference gives no mutating access level,
 * and the cryptographic operations, which the guide's log entry examples record read-only.
 *
 * <p>The record follows the guide's per-operation examples ({@code ct-<operation>.html}):
 * <ul>
 *   <li>{@code requestParameters} and {@code responseElements} are the request's and the result's
 *   members with a lower first letter, typed as botocore's KMS model types them, without the
 *   plaintext the model marks sensitive and without any binary member: "The ciphertext in the
 *   request and the plaintext in the response are omitted" (Decrypt), and the ReEncrypt, Sign and
 *   ImportKeyMaterial examples carry no ciphertext, message or import token. A timestamp is written
 *   as those examples write one ({@code "validTo": "May 21, 2025, 5:47:45 AM"},
 *   {@code "creationDate": "Aug 10, 2022, 10:38:27 PM"}).</li>
 *   <li>A Decrypt record "always includes the encryptionAlgorithm in the requestParameters even if
 *   the encryption algorithm wasn't specified in the request", and the key it used as {@code keyId}.</li>
 *   <li>"some fields are omitted ... the response to GetKeyPolicy or any cryptographic operation":
 *   their {@code responseElements} is null, as for every read-only call.</li>
 *   <li>"AWS KMS records the key ARN of the affected KMS key in the responseElements.keyId element
 *   of the log entry, even when the AWS KMS API operation doesn't return the key ARN", for the
 *   operations {@link #KEY_ARN_IN_RESPONSE} lists. A CreateGrant record carries the grant's ID and
 *   that ARN, not its grant token.</li>
 *   <li>{@code resources} lists the KMS keys the call used, as {@code AWS::KMS::Key}: the source and
 *   then the destination key of a ReEncrypt, the key then its alias for a CreateAlias, the alias then
 *   its key for an UpdateAlias or a DeleteAlias, and the primary key, not the replica, for a
 *   ReplicateKey, as those examples list them. A call that uses no key has
 *   {@code "resources": []}, as the ListAliases and GenerateRandom examples.</li>
 * </ul>
 *
 * <p>Not recorded: the {@code additionalEventData.keyMaterialId} of a cryptographic operation, the
 * {@code CreateKey} entry a {@code ReplicateKey} request also results in, and the {@code DeleteKey}
 * and {@code RotateKey} events KMS logs when it deletes or rotates a key on its own, which Floci
 * does not do.
 */
@ApplicationScoped
public class KmsCloudTrailEvents implements ManagementEventSource {

    private static final Logger LOG = Logger.getLogger(KmsCloudTrailEvents.class);
    private static final String SERVICE = "kms";
    private static final String EVENT_SOURCE = ServicePrincipals.of(SERVICE);
    private static final String KEY_TYPE = "AWS::KMS::Key";
    private static final CloudTrailShapes.JsonStyle STYLE = new CloudTrailShapes.JsonStyle(true,
            DateTimeFormatter.ofPattern("MMM d, yyyy, h:mm:ss a", Locale.US).withZone(ZoneOffset.UTC));

    /** The operations whose record carries the key's ARN as {@code responseElements.keyId} (the guide's list). */
    static final Set<String> KEY_ARN_IN_RESPONSE = Set.of("CreateAlias", "CreateGrant", "DeleteAlias",
            "DisableKey", "EnableKey", "EnableKeyRotation", "ImportKeyMaterial", "TagResource", "UntagResource",
            "UpdateAlias", "UpdatePrimaryRegion");

    private final CloudTrailService cloudTrail;
    private final KmsService kms;
    private final RequestContext requestContext;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;

    @Inject
    public KmsCloudTrailEvents(CloudTrailService cloudTrail, KmsService kms, RequestContext requestContext,
                               CurrentVertxRequest currentRequest, ObjectMapper mapper) {
        this.cloudTrail = cloudTrail;
        this.kms = kms;
        this.requestContext = requestContext;
        this.currentRequest = currentRequest;
        this.mapper = mapper;
    }

    /**
     * The ARN of the key {@code request} names, read before KMS runs the call, since a DeleteAlias
     * leaves no alias to resolve afterwards; null when it names none the account holds.
     */
    String keyNamed(String action, JsonNode request, String region) {
        String named = switch (action) {
            case "CreateAlias", "UpdateAlias" -> request.path("TargetKeyId").asText(null);
            case "DeleteAlias" -> request.path("AliasName").asText(null);
            case "ReEncrypt" -> request.path("SourceKeyId").asText(null);
            default -> request.path("KeyId").asText(null);
        };
        return named == null ? null : kms.findKeyArn(named, region).orElse(null);
    }

    /**
     * Records the call {@code response} answered, or that failed with {@code error} when it is set, as the
     * caller the request was signed by; {@code keyArn} is {@link #keyNamed}'s answer.
     */
    void record(String action, JsonNode request, String region, String keyArn, Response response,
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
                } else if (response.getStatus() < 400) {
                    // A call that answers nothing (CreateAlias) still succeeded.
                    answered = response.getEntity() == null
                            ? mapper.createObjectNode() : mapper.valueToTree(response.getEntity());
                }
            }
            ObjectNode parameters = shapes.requestParameters(action, request, STYLE);
            if ("Decrypt".equals(action)) {
                parameters = decryptParameters(parameters, answered, keyArn);
            }
            ObjectNode result = answered != null && !catalog.isReadOnly(action)
                    ? resultElements(action, shapes.result(action, answered, STYLE), keyArn) : null;
            cloudTrail.emitManagementEvent(new CloudTrailService.ManagementEventInput(EVENT_SOURCE, action, region,
                    requestContext.getAccessKeyId(), parameters, result, catalog.isReadOnly(action),
                    sourceIp(currentRequest.getCurrent()), userAgent(currentRequest.getCurrent()), null,
                    errorCode, errorMessage, false, null, null, resources(action, request, answered, keyArn)));
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
     * The record of a call IAM enforcement refused with {@code refusal} before KMS ran it, with
     * {@code "requestParameters": null} as AWS records an authorization refusal and, as {@link #REFUSED}, the
     * message the refusal answered with; null for a call that is not a management event.
     */
    @Override
    public CloudTrailService.ManagementEventInput refused(String operation, String accessKeyId, String region,
                                                          RoutingContext routingContext, Response refusal) {
        CloudTrailEventCatalog catalog = CloudTrailEventCatalog.of(SERVICE);
        if (!catalog.isManagementEvent(operation)) {
            return null;
        }
        return new CloudTrailService.ManagementEventInput(EVENT_SOURCE, operation, region, accessKeyId, null, null,
                catalog.isReadOnly(operation), sourceIp(routingContext), userAgent(routingContext), null,
                REFUSED, refusalMessage(refusal));
    }

    private ObjectNode decryptParameters(ObjectNode parameters, JsonNode answered, String keyArn) {
        ObjectNode read = parameters == null ? mapper.createObjectNode() : parameters;
        String usedKey = answered == null ? keyArn : answered.path("KeyId").asText(keyArn);
        if (usedKey != null) {
            read.put("keyId", usedKey);
        }
        if (!read.has("encryptionAlgorithm")) {
            read.put("encryptionAlgorithm", answered == null
                    ? "SYMMETRIC_DEFAULT" : answered.path("EncryptionAlgorithm").asText("SYMMETRIC_DEFAULT"));
        }
        return read;
    }

    private ObjectNode resultElements(String action, ObjectNode result, String keyArn) {
        ObjectNode read = result == null ? mapper.createObjectNode() : result;
        if ("CreateGrant".equals(action)) {
            read.remove("grantToken");
        }
        if (KEY_ARN_IN_RESPONSE.contains(action) && keyArn != null) {
            read.put("keyId", keyArn);
        }
        return read.isEmpty() ? null : read;
    }

    /** The keys the call used, each as an {@code AWS::KMS::Key} resource. */
    private ArrayNode resources(String action, JsonNode request, JsonNode answered, String keyArn) {
        List<String> arns = new ArrayList<>();
        switch (action) {
            case "CreateKey" -> add(arns, answered == null ? null : answered.path("KeyMetadata").path("Arn").asText(null));
            case "ReEncrypt" -> {
                add(arns, answered == null ? keyArn : answered.path("SourceKeyId").asText(keyArn));
                add(arns, answered == null ? null : answered.path("KeyId").asText(null));
            }
            case "Decrypt" -> add(arns, answered == null ? keyArn : answered.path("KeyId").asText(keyArn));
            case "CreateAlias" -> {
                add(arns, keyArn);
                add(arns, aliasArn(keyArn, request.path("AliasName").asText(null)));
            }
            case "UpdateAlias", "DeleteAlias" -> {
                add(arns, aliasArn(keyArn, request.path("AliasName").asText(null)));
                add(arns, keyArn);
            }
            default -> add(arns, keyArn);
        }
        ArrayNode resources = mapper.createArrayNode();
        for (String arn : arns) {
            resources.addObject().put("accountId", AwsArnUtils.accountOrDefault(arn, ""))
                    .put("type", KEY_TYPE).put("ARN", arn);
        }
        return resources;
    }

    /** The ARN of {@code alias} ({@code alias/<name>}) in the account and Region of {@code keyArn}. */
    private static String aliasArn(String keyArn, String alias) {
        if (keyArn == null || alias == null || !keyArn.contains(":key/")) {
            return null;
        }
        return keyArn.substring(0, keyArn.indexOf(":key/")) + ":" + alias;
    }

    private static void add(List<String> arns, String arn) {
        if (arn != null && !arn.isBlank()) {
            arns.add(arn);
        }
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
