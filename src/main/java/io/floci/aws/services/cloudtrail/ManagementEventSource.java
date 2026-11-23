package io.floci.aws.services.cloudtrail;

import io.floci.aws.core.common.AwsErrorResponse;
import io.floci.aws.core.common.XmlParser;
import io.vertx.ext.web.RoutingContext;
import jakarta.ws.rs.core.Response;

/**
 * A service whose API calls CloudTrail records as management events, asked for the record of a
 * call IAM enforcement refused before the service ran it. Each such service has one, so the
 * enforcement filter records a refusal without knowing which service's calls are recorded, or how.
 */
public interface ManagementEventSource {

    /** The credential scope of the service whose calls this records ({@code iam}, {@code sqs}). */
    String credentialScope();

    /**
     * The record of {@code operation}, which IAM enforcement refused with {@code refusal}, carrying the
     * message the refusal answers with; null for an operation CloudTrail does not record as a management
     * event.
     */
    CloudTrailService.ManagementEventInput refused(String operation, String accessKeyId, String region,
                                                   RoutingContext routingContext, Response refusal);

    /**
     * The errorCode a call IAM enforcement refused is recorded under, whatever code its service answers it
     * with: records of refused Lambda and CloudWatch calls since 2024 carry {@code "errorCode": "AccessDenied"},
     * as IAM's own refusals do.
     */
    String REFUSED = "AccessDenied";

    /**
     * The message {@code refusal} answers with: a JSON error's {@code message}, or a Query or XML error's
     * {@code Message}; null for one that carries neither, such as a CBOR one.
     */
    default String refusalMessage(Response refusal) {
        if (refusal == null) {
            return null;
        }
        if (refusal.getEntity() instanceof AwsErrorResponse error) {
            return error.message();
        }
        return refusal.getEntity() instanceof String xml ? XmlParser.extractFirst(xml, "Message", null) : null;
    }
}
