package io.floci.aws.services.cloudtrail;

import io.floci.aws.services.cloudtrail.model.AdvancedFieldSelector;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link CloudTrailService}'s advanced-selector field matcher, the building
 * block for AdvancedEventSelectors evaluation. Full capture/exclusion pipeline coverage lives
 * in {@code CloudTrailAdvancedSelectorsIntegrationTest}.
 */
class CloudTrailAdvancedSelectorMatchingTest {

    private static final String OTHER_BUCKET_ARN = "arn:aws:s3:::other-bucket/key";
    private static final String LOG_BUCKET_ARN = "arn:aws:s3:::log-bucket/some-key";
    private static final String OBJECT_TYPE = "AWS::S3::Object";
    private static final String BUCKET_TYPE = "AWS::S3::Bucket";

    @Test
    void eventCategoryEquals_matchesDataEvents() {
        AdvancedFieldSelector fs = new AdvancedFieldSelector(
                "eventCategory", List.of("Data"), null, null, null, null, null);
        assertTrue(CloudTrailService.matchesAdvancedFieldSelector(fs, event(OTHER_BUCKET_ARN, OBJECT_TYPE)));
    }

    @Test
    void eventCategoryEquals_rejectsNonDataValue() {
        AdvancedFieldSelector fs = new AdvancedFieldSelector(
                "eventCategory", List.of("Management"), null, null, null, null, null);
        assertFalse(CloudTrailService.matchesAdvancedFieldSelector(fs, event(OTHER_BUCKET_ARN, OBJECT_TYPE)));
    }

    @Test
    void resourcesTypeEquals_matchesS3Object() {
        AdvancedFieldSelector fs = new AdvancedFieldSelector(
                "resources.type", List.of("AWS::S3::Object"), null, null, null, null, null);
        assertTrue(CloudTrailService.matchesAdvancedFieldSelector(fs, event(OTHER_BUCKET_ARN, OBJECT_TYPE)));
    }

    @Test
    void resourcesTypeEquals_rejectsBucketLevelOperation() {
        // Bucket-level calls (ListObjects, no object key) are AWS::S3::Bucket resources:
        // an AWS::S3::Object DataResource selector must never match them.
        AdvancedFieldSelector fs = new AdvancedFieldSelector(
                "resources.type", List.of("AWS::S3::Object"), null, null, null, null, null);
        assertFalse(CloudTrailService.matchesAdvancedFieldSelector(fs, event("arn:aws:s3:::other-bucket", BUCKET_TYPE)));
    }

    @Test
    void resourcesArnNotStartsWith_excludesMatchingPrefix() {
        AdvancedFieldSelector fs = new AdvancedFieldSelector(
                "resources.ARN", null, null, null, List.of("arn:aws:s3:::log-bucket/"), null, null);
        assertFalse(CloudTrailService.matchesAdvancedFieldSelector(fs, event(LOG_BUCKET_ARN, OBJECT_TYPE)));
        assertTrue(CloudTrailService.matchesAdvancedFieldSelector(fs, event(OTHER_BUCKET_ARN, OBJECT_TYPE)));
    }

    @Test
    void resourcesArnStartsWith_onlyMatchesGivenPrefix() {
        AdvancedFieldSelector fs = new AdvancedFieldSelector(
                "resources.ARN", null, null, List.of("arn:aws:s3:::log-bucket/"), null, null, null);
        assertTrue(CloudTrailService.matchesAdvancedFieldSelector(fs, event(LOG_BUCKET_ARN, OBJECT_TYPE)));
        assertFalse(CloudTrailService.matchesAdvancedFieldSelector(fs, event(OTHER_BUCKET_ARN, OBJECT_TYPE)));
    }

    @Test
    void resourcesArnEndsWithAndNotEndsWith() {
        AdvancedFieldSelector endsWith = new AdvancedFieldSelector(
                "resources.ARN", null, null, null, null, List.of("some-key"), null);
        assertTrue(CloudTrailService.matchesAdvancedFieldSelector(endsWith, event(LOG_BUCKET_ARN, OBJECT_TYPE)));

        AdvancedFieldSelector notEndsWith = new AdvancedFieldSelector(
                "resources.ARN", null, null, null, null, null, List.of("some-key"));
        assertFalse(CloudTrailService.matchesAdvancedFieldSelector(notEndsWith, event(LOG_BUCKET_ARN, OBJECT_TYPE)));
    }

    @Test
    void readOnlyEquals_matchesTheEventsAccessLevel() {
        AdvancedFieldSelector readOnly = new AdvancedFieldSelector(
                "readOnly", List.of("true"), null, null, null, null, null);
        AdvancedFieldSelector writeOnly = new AdvancedFieldSelector(
                "readOnly", List.of("false"), null, null, null, null, null);
        assertTrue(CloudTrailService.matchesAdvancedFieldSelector(readOnly, event("GetObject")));
        assertFalse(CloudTrailService.matchesAdvancedFieldSelector(readOnly, event("PutObject")));
        assertTrue(CloudTrailService.matchesAdvancedFieldSelector(writeOnly, event("PutObject")));
        assertFalse(CloudTrailService.matchesAdvancedFieldSelector(writeOnly, event("GetObject")));
    }

    @Test
    void eventNameEqualsAndNotEquals() {
        AdvancedFieldSelector equals = new AdvancedFieldSelector(
                "eventName", List.of("PutObject", "DeleteObject"), null, null, null, null, null);
        assertTrue(CloudTrailService.matchesAdvancedFieldSelector(equals, event("DeleteObject")));
        assertFalse(CloudTrailService.matchesAdvancedFieldSelector(equals, event("GetObject")));

        AdvancedFieldSelector notEquals = new AdvancedFieldSelector(
                "eventName", null, List.of("GetObject"), null, null, null, null);
        assertFalse(CloudTrailService.matchesAdvancedFieldSelector(notEquals, event("GetObject")));
        assertTrue(CloudTrailService.matchesAdvancedFieldSelector(notEquals, event("PutObject")));
    }

    @Test
    void eventSourceAndEventType_areThoseOfAnS3ApiCall() {
        AdvancedFieldSelector source = new AdvancedFieldSelector(
                "eventSource", List.of("s3.amazonaws.com"), null, null, null, null, null);
        AdvancedFieldSelector notServiceEvents = new AdvancedFieldSelector(
                "eventType", null, List.of("AwsServiceEvent"), null, null, null, null);
        assertTrue(CloudTrailService.matchesAdvancedFieldSelector(source, event("PutObject")));
        assertTrue(CloudTrailService.matchesAdvancedFieldSelector(notServiceEvents, event("PutObject")));
    }

    @Test
    void userIdentityArn_isResolvedOnlyWhenASelectorFiltersOnIt() {
        AtomicInteger lookups = new AtomicInteger();
        CloudTrailService.DataEventFields event = new CloudTrailService.DataEventFields(
                "PutObject", OBJECT_TYPE, OTHER_BUCKET_ARN, () -> {
                    lookups.incrementAndGet();
                    return "arn:aws:iam::000000000000:user/alice";
                });
        AdvancedFieldSelector type = new AdvancedFieldSelector(
                "resources.type", List.of(OBJECT_TYPE), null, null, null, null, null);
        assertTrue(CloudTrailService.matchesAdvancedFieldSelector(type, event));
        assertEquals(0, lookups.get());

        AdvancedFieldSelector user = new AdvancedFieldSelector(
                "userIdentity.arn", null, null, null, null, List.of(":user/alice"), null);
        AdvancedFieldSelector notUser = new AdvancedFieldSelector(
                "userIdentity.arn", null, List.of("arn:aws:iam::000000000000:user/alice"),
                null, null, null, null);
        assertTrue(CloudTrailService.matchesAdvancedFieldSelector(user, event));
        assertFalse(CloudTrailService.matchesAdvancedFieldSelector(notUser, event));
        assertEquals(1, lookups.get());
    }

    @Test
    void unknownField_neverMatches() {
        AdvancedFieldSelector fs = new AdvancedFieldSelector(
                "requestParameters.key", List.of("key"), null, null, null, null, null);
        assertFalse(CloudTrailService.matchesAdvancedFieldSelector(fs, event(OTHER_BUCKET_ARN, OBJECT_TYPE)));
    }

    private static CloudTrailService.DataEventFields event(String arn, String resourceType) {
        return new CloudTrailService.DataEventFields("PutObject", resourceType, arn, () -> "");
    }

    private static CloudTrailService.DataEventFields event(String eventName) {
        return new CloudTrailService.DataEventFields(eventName, OBJECT_TYPE, OTHER_BUCKET_ARN, () -> "");
    }
}
