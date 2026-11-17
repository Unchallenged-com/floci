package io.floci.aws.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AccountResolver;
import io.floci.aws.core.common.AwsPartition;
import io.floci.aws.core.common.AwsPartitions;
import io.floci.aws.core.common.RequestContext;
import io.floci.aws.core.common.ServicePrincipals;
import io.floci.aws.core.common.XmlParser;
import io.floci.aws.services.cloudtrail.CloudTrailService;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Records IAM API calls as CloudTrail management events, as the IAM User Guide says CloudTrail
 * does: "CloudTrail logs all authenticated API requests to IAM and AWS STS API operations"
 * (https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html). A call is recorded
 * whether it succeeds, fails, or is refused by IAM enforcement.
 *
 * <p>The record follows that page's and the CloudTrail log file examples' IAM events
 * (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html):
 * {@code eventSource} {@code iam.amazonaws.com}, {@code awsRegion} the partition's IAM signing Region
 * ({@code us-east-1} in {@code aws}), {@code requestParameters} the request's members with a lower
 * first letter, and {@code responseElements} null for a read-only call, as "When logging a read-only
 * event, CloudTrail redacts the responseElements information", and the call's result otherwise,
 * timestamps written as those examples write them ({@code Jul 19, 2023 9:25:09 PM}).
 *
 * <p>An error IAM models is recorded under its error shape's name ({@code NoSuchEntityException}),
 * as AWS records them. A call IAM enforcement refuses carries the refusal in the format IAM's guide
 * gives access denied messages, "User user is not authorized to perform action on resource because
 * context" (https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html), and
 * {@code "requestParameters": null}, as AWS records an authorization refusal.
 */
@ApplicationScoped
public class IamCloudTrailEvents {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String EVENT_SOURCE = ServicePrincipals.of("iam");

    /**
     * The prefixes of the IAM actions AWS's Service Reference Information
     * (https://servicereference.us-east-1.amazonaws.com/v1/iam/iam.json) marks neither
     * {@code IsWrite}, {@code IsPermissionManagement} nor {@code IsTaggingOnly}: every such action
     * starts with one of these, and no other action does. CloudTrail "considers an action read-only
     * if it does not have any mutating effect on a resource".
     */
    private static final List<String> READ_ONLY_PREFIXES = List.of("Get", "List", "Generate", "Simulate");

    /**
     * Request members that carry a password. CloudTrail records {@code ChangePassword}, whose two
     * members are both passwords, with {@code "requestParameters": null}
     * (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html).
     */
    private static final Set<String> SECRET_REQUEST_MEMBERS = Set.of("password", "oldPassword", "newPassword");

    /**
     * Result members that carry a secret. CloudTrail includes "the full responseElements except
     * secretAccessKey" for the STS calls that return credentials, and removes key material from
     * the results it records.
     */
    private static final Set<String> SECRET_RESULT_MEMBERS = Set.of(
            "secretAccessKey", "servicePassword", "base32StringSeed", "qRCodePNG", "privateKey");

    /** IAM's error codes and the error shapes that answer them, from IAM's service model. */
    private static final Map<String, String> MODELED_ERRORS = Map.ofEntries(
            Map.entry("ConcurrentModification", "ConcurrentModificationException"),
            Map.entry("ReportExpired", "CredentialReportExpiredException"),
            Map.entry("ReportNotPresent", "CredentialReportNotPresentException"),
            Map.entry("ReportInProgress", "CredentialReportNotReadyException"),
            Map.entry("DeleteConflict", "DeleteConflictException"),
            Map.entry("DuplicateCertificate", "DuplicateCertificateException"),
            Map.entry("DuplicateSSHPublicKey", "DuplicateSSHPublicKeyException"),
            Map.entry("EntityAlreadyExists", "EntityAlreadyExistsException"),
            Map.entry("EntityTemporarilyUnmodifiable", "EntityTemporarilyUnmodifiableException"),
            Map.entry("FeatureDisabled", "FeatureDisabledException"),
            Map.entry("FeatureEnabled", "FeatureEnabledException"),
            Map.entry("InvalidAuthenticationCode", "InvalidAuthenticationCodeException"),
            Map.entry("InvalidCertificate", "InvalidCertificateException"),
            Map.entry("InvalidInput", "InvalidInputException"),
            Map.entry("InvalidPublicKey", "InvalidPublicKeyException"),
            Map.entry("InvalidUserType", "InvalidUserTypeException"),
            Map.entry("KeyPairMismatch", "KeyPairMismatchException"),
            Map.entry("LimitExceeded", "LimitExceededException"),
            Map.entry("MalformedCertificate", "MalformedCertificateException"),
            Map.entry("MalformedPolicyDocument", "MalformedPolicyDocumentException"),
            Map.entry("NameConflict", "NameConflictException"),
            Map.entry("NoSuchEntity", "NoSuchEntityException"),
            Map.entry("OpenIdIdpCommunicationError", "OpenIdIdpCommunicationErrorException"),
            Map.entry("PasswordPolicyViolation", "PasswordPolicyViolationException"),
            Map.entry("PolicyEvaluation", "PolicyEvaluationException"),
            Map.entry("PolicyNotAttachable", "PolicyNotAttachableException"),
            Map.entry("ReportGenerationLimitExceeded", "ReportGenerationLimitExceededException"),
            Map.entry("RoleModified", "RoleModifiedException"),
            Map.entry("RoleTemplateDisabled", "RoleTemplateDisabledException"),
            Map.entry("ServiceFailure", "ServiceFailureException"),
            Map.entry("NotSupportedService", "ServiceNotSupportedException"),
            Map.entry("UnmodifiableEntity", "UnmodifiableEntityException"),
            Map.entry("UnrecognizedPublicKeyEncoding", "UnrecognizedPublicKeyEncodingException"));

    /** Result members IAM types as numbers: its counts, ages, lengths, durations and policy positions. */
    private static final Pattern NUMBER_MEMBER =
            Pattern.compile(".*(Count|Age|Length|Prevention|Duration)|line|column");
    private static final DateTimeFormatter RECORD_TIMESTAMP =
            DateTimeFormatter.ofPattern("MMM d, yyyy h:mm:ss a", Locale.US).withZone(ZoneOffset.UTC);
    private static final QueryResultElements RESULTS =
            new QueryResultElements(NUMBER_MEMBER, RECORD_TIMESTAMP, SECRET_RESULT_MEMBERS);

    private final CloudTrailService cloudTrail;
    private final AccountResolver accounts;
    private final RequestContext requestContext;
    private final CurrentVertxRequest currentRequest;

    @Inject
    public IamCloudTrailEvents(CloudTrailService cloudTrail, AccountResolver accounts,
                               RequestContext requestContext, CurrentVertxRequest currentRequest) {
        this.cloudTrail = cloudTrail;
        this.accounts = accounts;
        this.requestContext = requestContext;
        this.currentRequest = currentRequest;
    }

    /** Records the call {@code response} answered. */
    public void record(String action, MultivaluedMap<String, String> params, String authorization,
                       Response response) {
        if (!cloudTrail.hasTrails() || response == null || !(response.getEntity() instanceof String xml)) {
            return;
        }
        String errorCode = response.getStatus() >= 400 ? XmlParser.extractFirst(xml, "Code", null) : null;
        if ("UnsupportedOperation".equals(errorCode)) {
            return;
        }
        String errorMessage = errorCode == null ? null : XmlParser.extractFirst(xml, "Message", null);
        ObjectNode result = errorCode == null && recordsResult(action) ? result(action, xml) : null;
        cloudTrail.emitManagementEvent(event(action, params, accounts.extractAccessKeyId(authorization),
                requestContext.getRegion(), request(currentRequest.getCurrent()), result,
                XmlParser.extractFirst(xml, "RequestId", null), errorCode, errorMessage));
    }

    /**
     * The record of a call IAM enforcement refused before IAM ran it, named after the request's
     * {@code Action}; null for a request that names none.
     */
    public static CloudTrailService.ManagementEventInput denied(MultivaluedMap<String, String> params,
                                                                String accessKeyId, String region,
                                                                RoutingContext routingContext,
                                                                String errorCode, String errorMessage) {
        String action = params.getFirst("Action");
        if (action == null || action.isBlank()) {
            return null;
        }
        return event(action, null, accessKeyId, region, request(routingContext), null, null,
                errorCode, errorMessage);
    }

    /** Whether the record carries the call's result: a call that is not read-only. */
    static boolean recordsResult(String action) {
        return !isReadOnly(action);
    }

    /**
     * IAM's modeled errors, which CloudTrail records under the error shape's name rather than the
     * code IAM answers with ({@code NoSuchEntity} is recorded as {@code NoSuchEntityException}): the
     * error shapes of IAM's model whose code differs from their name. An error IAM does not model,
     * such as {@code AccessDenied}, is recorded as answered.
     */
    static String recordedErrorCode(String code) {
        return code == null ? null : MODELED_ERRORS.getOrDefault(code, code);
    }

    /** Whether CloudTrail records {@code action} as read-only. */
    static boolean isReadOnly(String action) {
        return READ_ONLY_PREFIXES.stream().anyMatch(action::startsWith);
    }

    private static HttpServerRequest request(RoutingContext routingContext) {
        return routingContext == null ? null : routingContext.request();
    }

    private static CloudTrailService.ManagementEventInput event(String action, MultivaluedMap<String, String> params,
                                                                String accessKeyId, String region,
                                                                HttpServerRequest request, ObjectNode result,
                                                                String requestId, String errorCode,
                                                                String errorMessage) {
        String sourceIp = request == null || request.remoteAddress() == null ? null : request.remoteAddress().host();
        String userAgent = request == null ? null : request.getHeader("User-Agent");
        return new CloudTrailService.ManagementEventInput(EVENT_SOURCE, action, iamRegion(region), accessKeyId,
                params == null ? null : requestParameters(action, params), result, isReadOnly(action), sourceIp,
                userAgent, requestId, recordedErrorCode(errorCode), errorMessage);
    }

    /** IAM's events are recorded in the Region IAM's endpoint signs for in the request's partition. */
    private static String iamRegion(String region) {
        AwsPartition partition = AwsPartitions.forRegionOrCommercial(region);
        return partition.globalEndpoint("iam").map(AwsPartition.GlobalEndpoint::signingRegion).orElse(region);
    }

    static ObjectNode requestParameters(String action, MultivaluedMap<String, String> params) {
        ObjectNode read = IamRequestShapes.read(action, params);
        if (read == null) {
            read = MAPPER.createObjectNode();
            for (Map.Entry<String, List<String>> param : params.entrySet()) {
                String name = param.getKey();
                if (!name.contains(".") && !"Action".equals(name) && !"Version".equals(name)
                        && !param.getValue().isEmpty()) {
                    read.put(lowerFirst(name), param.getValue().getFirst());
                }
            }
        }
        read.remove(SECRET_REQUEST_MEMBERS);
        return read.isEmpty() ? null : read;
    }

    /** The call's {@code <ActionResult>}, or null for a call whose result carries nothing. */
    static ObjectNode result(String action, String xml) {
        return RESULTS.read(action, xml);
    }

    private static String lowerFirst(String name) {
        return QueryResultElements.lowerFirst(name);
    }
}
