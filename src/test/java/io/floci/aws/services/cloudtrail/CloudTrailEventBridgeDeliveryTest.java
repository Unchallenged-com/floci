package io.floci.aws.services.cloudtrail;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.services.eventbridge.EventBridgeService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.RejectedExecutionException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class CloudTrailEventBridgeDeliveryTest {
    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "661100000003";
    private final ObjectMapper mapper = new ObjectMapper();
    private EventBridgeService events;
    private CloudTrailEventBridgeDelivery delivery;
    private Deque<Runnable> deliveries;

    @BeforeEach
    void setUp() {
        events = mock(EventBridgeService.class);
        deliveries = new ArrayDeque<>();
        delivery = new CloudTrailEventBridgeDelivery(events, deliveries::addLast);
    }

    @Test
    void theRecordReachesItsServicesDefaultBusInTheBackgroundAsItsDetail() {
        ObjectNode record = record("lambda.amazonaws.com", "AwsApiCall");
        delivery.deliver(record);
        verifyNoInteractions(events);
        assertEquals(1, deliveries.size());
        deliveries.removeFirst().run();
        verify(events).publishServiceEvent("aws.lambda", "AWS API Call via CloudTrail", record.toString(), null,
                REGION);
    }

    @Test
    void theDetailTypeFollowsTheRecordsEventType() {
        ObjectNode record = record("secretsmanager.amazonaws.com", "AwsServiceEvent");
        delivery.deliver(record);
        deliveries.removeFirst().run();
        verify(events).publishServiceEvent("aws.secretsmanager", "AWS Service Event via CloudTrail",
                record.toString(), null, REGION);
    }

    @Test
    void queuedDeliveryUsesASnapshotOfTheRecord() {
        ObjectNode record = record("ec2.amazonaws.com", "AwsApiCall");
        String detail = record.toString();
        delivery.deliver(record);
        record.removeAll();
        deliveries.removeFirst().run();
        verify(events).publishServiceEvent("aws.ec2", "AWS API Call via CloudTrail", detail, null, REGION);
    }

    @Test
    void aRecordOver256KbIsNotSent() {
        ObjectNode record = record("lambda.amazonaws.com", "AwsApiCall");
        record.putObject("requestParameters").put("padding", "x".repeat(CloudTrailEventBridgeDelivery.MAX_EVENT_BYTES));
        delivery.deliver(record);
        assertTrue(deliveries.isEmpty());
    }

    @Test
    void anEventSourceOutsideAmazonawsComHasNoSource() {
        assertEquals("aws.iam", CloudTrailEventBridgeDelivery.source("iam.amazonaws.com"));
        assertNull(CloudTrailEventBridgeDelivery.source("example.com"));
        assertNull(CloudTrailEventBridgeDelivery.source(".amazonaws.com"));
    }

    @Test
    void rejectedQueueDoesNotRunDeliveryInTheCallOrFailIt() {
        delivery = new CloudTrailEventBridgeDelivery(events,
                task -> { throw new RejectedExecutionException("example full queue"); });
        assertDoesNotThrow(() -> delivery.deliver(record("lambda.amazonaws.com", "AwsApiCall")));
        verifyNoInteractions(events);
    }

    @Test
    void backgroundDeliveryFailureIsContained() {
        doThrow(new IllegalStateException("example delivery failure")).when(events)
                .publishServiceEvent(anyString(), anyString(), anyString(), any(), anyString());
        delivery.deliver(record("lambda.amazonaws.com", "AwsApiCall"));
        assertDoesNotThrow(() -> deliveries.removeFirst().run());
    }

    private ObjectNode record(String eventSource, String eventType) {
        return mapper.createObjectNode().put("eventName", "Example").put("eventSource", eventSource)
                .put("eventType", eventType).put("recipientAccountId", ACCOUNT).put("awsRegion", REGION);
    }
}
