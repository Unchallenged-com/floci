package io.floci.aws.services.cloudtrail.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public record Trail(
        @JsonProperty("Name") String name,
        @JsonProperty("TrailARN") String trailArn,
        @JsonProperty("S3BucketName") String s3BucketName,
        @JsonProperty("S3KeyPrefix") String s3KeyPrefix,
        @JsonProperty("SnsTopicARN") String snsTopicArn,
        @JsonProperty("IncludeGlobalServiceEvents") boolean includeGlobalServiceEvents,
        @JsonProperty("IsMultiRegionTrail") boolean isMultiRegionTrail,
        @JsonProperty("HomeRegion") String homeRegion,
        @JsonProperty("LogFileValidationEnabled") boolean logFileValidationEnabled,
        @JsonProperty("HasCustomEventSelectors") boolean hasCustomEventSelectors,
        @JsonProperty("HasInsightSelectors") boolean hasInsightSelectors,
        @JsonProperty("IsOrganizationTrail") boolean isOrganizationTrail,
        @JsonProperty("KmsKeyId") String kmsKeyId,
        @JsonProperty("CloudWatchLogsLogGroupArn") String cloudWatchLogsLogGroupArn,
        @JsonProperty("CloudWatchLogsRoleArn") String cloudWatchLogsRoleArn,
        @JsonProperty("RecursiveLogging") Boolean recursiveLogging) {

    /** "The default value is true", which a trail stored before the setting existed also reads as. */
    public Trail {
        recursiveLogging = recursiveLogging == null ? Boolean.TRUE : recursiveLogging;
    }

    /** A trail with recursive logging on, its default. */
    public Trail(String name, String trailArn, String s3BucketName, String s3KeyPrefix, String snsTopicArn,
                 boolean includeGlobalServiceEvents, boolean isMultiRegionTrail, String homeRegion,
                 boolean logFileValidationEnabled, boolean hasCustomEventSelectors, boolean hasInsightSelectors,
                 boolean isOrganizationTrail, String kmsKeyId, String cloudWatchLogsLogGroupArn,
                 String cloudWatchLogsRoleArn) {
        this(name, trailArn, s3BucketName, s3KeyPrefix, snsTopicArn, includeGlobalServiceEvents, isMultiRegionTrail,
                homeRegion, logFileValidationEnabled, hasCustomEventSelectors, hasInsightSelectors,
                isOrganizationTrail, kmsKeyId, cloudWatchLogsLogGroupArn, cloudWatchLogsRoleArn, Boolean.TRUE);
    }

    /** A trail without encryption or CloudWatch Logs delivery. */
    public Trail(String name, String trailArn, String s3BucketName, String s3KeyPrefix, String snsTopicArn,
                 boolean includeGlobalServiceEvents, boolean isMultiRegionTrail, String homeRegion,
                 boolean logFileValidationEnabled, boolean hasCustomEventSelectors, boolean hasInsightSelectors,
                 boolean isOrganizationTrail) {
        this(name, trailArn, s3BucketName, s3KeyPrefix, snsTopicArn, includeGlobalServiceEvents, isMultiRegionTrail,
                homeRegion, logFileValidationEnabled, hasCustomEventSelectors, hasInsightSelectors,
                isOrganizationTrail, null, null, null);
    }

    /** This trail with {@code recursiveLogging} set. */
    public Trail withRecursiveLogging(boolean enabled) {
        return new Trail(name, trailArn, s3BucketName, s3KeyPrefix, snsTopicArn, includeGlobalServiceEvents,
                isMultiRegionTrail, homeRegion, logFileValidationEnabled, hasCustomEventSelectors, hasInsightSelectors,
                isOrganizationTrail, kmsKeyId, cloudWatchLogsLogGroupArn, cloudWatchLogsRoleArn, enabled);
    }
}
