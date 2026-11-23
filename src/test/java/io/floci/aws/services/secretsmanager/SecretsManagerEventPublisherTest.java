package io.floci.aws.services.secretsmanager;

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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class SecretsManagerEventPublisherTest {
    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "661100000003";
    private static final String ARN = "arn:aws:secretsmanager:us-east-1:661100000003:secret:example";
    private final ObjectMapper mapper = new ObjectMapper();
    private EventBridgeService events;
    private SecretsManagerEventPublisher publisher;
    private Deque<Runnable> deliveries;

    @BeforeEach
    void setUp() {
        events = mock(EventBridgeService.class);
        deliveries = new ArrayDeque<>();
        publisher = new SecretsManagerEventPublisher(events, deliveries::addLast);
    }

    @Test
    void theRecordReachesTheDefaultBusInTheBackgroundAsItsDetail() {
        ObjectNode record = record();
        publisher.secretWritten("PutSecretValue", record);
        verifyNoInteractions(events);
        assertEquals(1, deliveries.size());
        deliveries.removeFirst().run();
        verify(events).publishServiceEvent("aws.secretsmanager", "AWS API Call via CloudTrail",
                record.toString(), ARN, REGION);
    }

    @Test
    void queuedDeliveryUsesASnapshotOfTheRecord() {
        ObjectNode record = record();
        String detail = record.toString();
        publisher.secretWritten("PutSecretValue", record);
        record.removeAll();
        deliveries.removeFirst().run();
        verify(events).publishServiceEvent("aws.secretsmanager", "AWS API Call via CloudTrail", detail, ARN, REGION);
    }

    @Test
    void rejectedQueueDoesNotRunDeliveryInTheWriteRequestOrFailTheWrite() {
        publisher = new SecretsManagerEventPublisher(events,
                task -> { throw new RejectedExecutionException("example full queue"); });
        assertDoesNotThrow(() -> publisher.secretWritten("PutSecretValue", record()));
        verifyNoInteractions(events);
    }

    @Test
    void backgroundDeliveryFailureIsContained() {
        doThrow(new IllegalStateException("example delivery failure")).when(events)
                .publishServiceEvent(anyString(), anyString(), anyString(), anyString(), anyString());
        publisher.secretWritten("PutSecretValue", record());
        assertDoesNotThrow(() -> deliveries.removeFirst().run());
    }

    private ObjectNode record() {
        ObjectNode record = mapper.createObjectNode().put("eventName", "PutSecretValue")
                .put("recipientAccountId", ACCOUNT).put("awsRegion", REGION);
        record.putObject("responseElements").put("arn", ARN);
        return record;
    }
}
