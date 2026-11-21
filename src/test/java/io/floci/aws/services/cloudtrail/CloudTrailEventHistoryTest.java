package io.floci.aws.services.cloudtrail;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AwsException;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Unit tests for {@link CloudTrailEventHistory}: retention, bounds, filters, paging and the rate limit. */
class CloudTrailEventHistoryTest {

    private static final String ACCOUNT = "111122223333";
    private static final String REGION = "us-east-1";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Instant NOW = Instant.parse("2026-11-21T12:00:00Z");

    private final MutableClock clock = new MutableClock(NOW);

    @Test
    void lookupAnswersTheMostRecentEventFirst() {
        CloudTrailEventHistory history = history(100, 0);
        history.add(ACCOUNT, REGION, record("e1", "PutSecretValue", NOW.minusSeconds(20)));
        history.add(ACCOUNT, REGION, record("e2", "UpdateSecret", NOW.minusSeconds(10)));
        assertEquals(List.of("e2", "e1"), ids(history.lookup(ACCOUNT, REGION, null, null, null, 50, null)));
    }

    @Test
    void eventsOfAnotherAccountOrRegionAreNotAnswered() {
        CloudTrailEventHistory history = history(100, 0);
        history.add(ACCOUNT, REGION, record("e1", "PutSecretValue", NOW));
        history.add("444455556666", REGION, record("other-account", "PutSecretValue", NOW));
        history.add(ACCOUNT, "eu-west-1", record("other-region", "PutSecretValue", NOW));
        assertEquals(List.of("e1"), ids(history.lookup(ACCOUNT, REGION, null, null, null, 50, null)));
    }

    @Test
    void eventsOlderThanNinetyDaysAreDropped() {
        CloudTrailEventHistory history = history(100, 0);
        history.add(ACCOUNT, REGION, record("old", "PutSecretValue", NOW.minus(Duration.ofDays(91))));
        history.add(ACCOUNT, REGION, record("recent", "PutSecretValue", NOW.minus(Duration.ofDays(89))));
        assertEquals(List.of("recent"), ids(history.lookup(ACCOUNT, REGION, null, null, null, 50, null)));
    }

    @Test
    void theOldestEventIsDroppedBeyondTheBound() {
        CloudTrailEventHistory history = history(2, 0);
        history.add(ACCOUNT, REGION, record("e1", "PutSecretValue", NOW.minusSeconds(3)));
        history.add(ACCOUNT, REGION, record("e2", "PutSecretValue", NOW.minusSeconds(2)));
        history.add(ACCOUNT, REGION, record("e3", "PutSecretValue", NOW.minusSeconds(1)));
        assertEquals(List.of("e3", "e2"), ids(history.lookup(ACCOUNT, REGION, null, null, null, 50, null)));
    }

    @Test
    void anAttributeAndATimeRangeFilterTheEvents() {
        CloudTrailEventHistory history = history(100, 0);
        history.add(ACCOUNT, REGION, record("put", "PutSecretValue", NOW.minusSeconds(30)));
        history.add(ACCOUNT, REGION, record("update", "UpdateSecret", NOW.minusSeconds(20)));
        history.add(ACCOUNT, REGION, record("put-later", "PutSecretValue", NOW.minusSeconds(10)));
        CloudTrailEventHistory.LookupAttribute puts =
                new CloudTrailEventHistory.LookupAttribute("EventName", "PutSecretValue");
        assertEquals(List.of("put-later", "put"), ids(history.lookup(ACCOUNT, REGION, puts, null, null, 50, null)));
        assertEquals(List.of("put"), ids(history.lookup(ACCOUNT, REGION, puts, NOW.minusSeconds(30),
                NOW.minusSeconds(15), 50, null)));
        assertEquals(List.of("put-later", "update"), ids(history.lookup(ACCOUNT, REGION,
                new CloudTrailEventHistory.LookupAttribute("Username", "alice"), NOW.minusSeconds(25), null, 50, null)));
    }

    @Test
    void aResourceIsNamedAsTheDocumentationShowsItsType() {
        assertEquals("CloudTrail_CloudWatchLogs_Role", LookupFields.resourceName(resource("AWS::IAM::Role",
                "arn:aws:iam::111122223333:role/service/CloudTrail_CloudWatchLogs_Role")));
        assertEquals("i-1234567", LookupFields.resourceName(resource("AWS::EC2::Instance",
                "arn:aws:ec2:us-east-1:111122223333:instance/i-1234567")));
        assertEquals("auto-scaling-test-group", LookupFields.resourceName(resource(
                "AWS::AutoScaling::AutoScalingGroup", "arn:aws:autoscaling:us-east-1:111122223333:autoScalingGroup:"
                        + "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111:autoScalingGroupName/auto-scaling-test-group")));
        String key = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        assertEquals(key, LookupFields.resourceName(resource("AWS::KMS::Key", key)));

        CloudTrailEventHistory history = history(100, 0);
        ObjectNode assumed = record("assume", "AssumeRole", NOW);
        assumed.putArray("resources").add(resource("AWS::IAM::Role", "arn:aws:iam::111122223333:role/deployer"));
        history.add(ACCOUNT, REGION, assumed);
        assertEquals(List.of("assume"), ids(history.lookup(ACCOUNT, REGION,
                new CloudTrailEventHistory.LookupAttribute("ResourceName", "deployer"), null, null, 50, null)));
        assertEquals("deployer", LookupFields.event(MAPPER, assumed).path("Resources").get(0)
                .path("ResourceName").asText());
    }

    @Test
    void pagesResumeFromTheTokenOfTheSameLookup() {
        CloudTrailEventHistory history = history(100, 0);
        for (int i = 1; i <= 3; i++) {
            history.add(ACCOUNT, REGION, record("e" + i, "PutSecretValue", NOW.minusSeconds(10 - i)));
        }
        CloudTrailEventHistory.Page first = history.lookup(ACCOUNT, REGION, null, null, null, 2, null);
        assertEquals(List.of("e3", "e2"), ids(first));
        assertNotNull(first.nextToken());
        CloudTrailEventHistory.Page second = history.lookup(ACCOUNT, REGION, null, null, null, 2, first.nextToken());
        assertEquals(List.of("e1"), ids(second));
        assertNull(second.nextToken());
        AwsException other = assertThrows(AwsException.class, () -> history.lookup(ACCOUNT, REGION,
                new CloudTrailEventHistory.LookupAttribute("EventName", "PutSecretValue"), null, null, 2,
                first.nextToken()));
        assertEquals("InvalidNextTokenException", other.getErrorCode());
    }

    @Test
    void aPageHoldsAtMostFiftyEvents() {
        CloudTrailEventHistory history = history(100, 0);
        for (int i = 0; i < 60; i++) {
            history.add(ACCOUNT, REGION, record("e" + i, "PutSecretValue", NOW.minusSeconds(100 - i)));
        }
        assertEquals(50, history.lookup(ACCOUNT, REGION, null, null, null, 1000, null).events().size());
    }

    @Test
    void aStartAfterTheEndIsRefused() {
        AwsException refused = assertThrows(AwsException.class, () -> history(100, 0)
                .lookup(ACCOUNT, REGION, null, NOW, NOW.minusSeconds(1), 50, null));
        assertEquals("InvalidTimeRangeException", refused.getErrorCode());
    }

    @Test
    void anUnknownAttributeKeyIsRefused() {
        AwsException refused = assertThrows(AwsException.class,
                () -> new CloudTrailEventHistory.LookupAttribute("UserName", "alice"));
        assertEquals("InvalidLookupAttributesException", refused.getErrorCode());
    }

    @Test
    void aThirdLookupWithinASecondIsThrottled() {
        CloudTrailEventHistory history = history(100, 2);
        history.lookup(ACCOUNT, REGION, null, null, null, 50, null);
        history.lookup(ACCOUNT, REGION, null, null, null, 50, null);
        AwsException throttled = assertThrows(AwsException.class,
                () -> history.lookup(ACCOUNT, REGION, null, null, null, 50, null));
        assertEquals("ThrottlingException", throttled.getErrorCode());
        history.lookup(ACCOUNT, "eu-west-1", null, null, null, 50, null);
        clock.advance(Duration.ofMillis(1001));
        history.lookup(ACCOUNT, REGION, null, null, null, 50, null);
    }

    private CloudTrailEventHistory history(int maxEvents, int lookupsPerSecond) {
        return new CloudTrailEventHistory(maxEvents, lookupsPerSecond, clock);
    }

    private static ObjectNode record(String id, String eventName, Instant time) {
        ObjectNode record = MAPPER.createObjectNode().put("eventID", id).put("eventName", eventName)
                .put("eventSource", "secretsmanager.amazonaws.com").put("eventTime", time.toString())
                .put("readOnly", false);
        record.putObject("userIdentity").put("type", "IAMUser").put("userName", "alice");
        return record;
    }

    private static ObjectNode resource(String type, String arn) {
        return MAPPER.createObjectNode().put("accountId", ACCOUNT).put("type", type).put("ARN", arn);
    }

    private static List<String> ids(CloudTrailEventHistory.Page page) {
        return ids(page.events());
    }

    private static List<String> ids(List<ObjectNode> events) {
        return events.stream().map(event -> event.path("eventID").asText()).toList();
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
