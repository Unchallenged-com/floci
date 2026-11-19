package io.floci.aws.services.cloudtrail;

import io.vertx.ext.web.RoutingContext;

/**
 * A service whose API calls CloudTrail records as management events, asked for the record of a
 * call IAM enforcement refused before the service ran it. Each such service has one, so the
 * enforcement filter records a refusal without knowing which service's calls are recorded, or how.
 */
public interface ManagementEventSource {

    /** The credential scope of the service whose calls this records ({@code iam}, {@code sqs}). */
    String credentialScope();

    /**
     * The record of {@code operation}, refused with {@code errorCode} and {@code errorMessage};
     * null for an operation CloudTrail does not record as a management event.
     */
    CloudTrailService.ManagementEventInput refused(String operation, String accessKeyId, String region,
                                                   RoutingContext routingContext, String errorCode,
                                                   String errorMessage);
}
