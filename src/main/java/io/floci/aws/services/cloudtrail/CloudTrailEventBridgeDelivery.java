package io.floci.aws.services.cloudtrail;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.RequestScopes;
import io.floci.aws.core.common.Resettable;
import io.floci.aws.services.eventbridge.EventBridgeService;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Puts every record a logging trail selects on EventBridge's default bus, in the background so a slow target
 * cannot hold the call it records: "CloudTrail sends the following types of events to the default EventBridge
 * event bus", and "To record events with one of the CloudTrail {@code detail-type} values, you must enable a
 * CloudTrail trail with logging"
 * (https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event-cloudtrail.html).
 *
 * <p>The event is the record's, as the Amazon EBS User Guide's {@code detachVolume} example (2024-03-18)
 * shows one (https://docs.aws.amazon.com/ebs/latest/userguide/ebs-cloud-watch-events.html): {@code source}
 * {@code aws.<service>} for the record's {@code <service>.amazonaws.com} ({@code aws.ec2}), {@code detail-type}
 * after the record's {@code eventType} ({@code AWS API Call via CloudTrail} for an {@code AwsApiCall}), the
 * record's account and Region, {@code "resources": []}, and the record itself as {@code detail}. A global
 * service's record is logged in US East (N. Virginia), so its event reaches that Region's bus. One event is put
 * however many trails select the record. A record over 256 KB is not sent: "CloudTrail does not send these
 * events to CloudWatch Logs or EventBridge"
 * (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html).
 * Which rules a read-only management event matches is EventBridge's
 * ({@code ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS}).
 */
@ApplicationScoped
public class CloudTrailEventBridgeDelivery implements Resettable {
    private static final Logger LOG = Logger.getLogger(CloudTrailEventBridgeDelivery.class);
    /** The largest event CloudTrail sends to EventBridge. */
    static final int MAX_EVENT_BYTES = 256 * 1024;
    /** The {@code detail-type} of each {@code eventType}, as the EventBridge User Guide lists them. */
    private static final Map<String, String> DETAIL_TYPES = Map.of(
            "AwsApiCall", "AWS API Call via CloudTrail",
            "AwsServiceEvent", "AWS Service Event via CloudTrail",
            "AwsConsoleSignIn", "AWS Console Signin via CloudTrail",
            "AwsConsoleAction", "AWS Console Action via CloudTrail",
            "AwsCloudTrailInsight", "AWS Insight via CloudTrail",
            "AwsVpceEvent", "AWS Network Activity Event via CloudTrail");
    private static final String SERVICE_DOMAIN = ".amazonaws.com";
    private static final long RESET_DRAIN_TIMEOUT_SECONDS = 30;

    private final EventBridgeService eventBridge;
    private final Executor deliveries;
    private final Object deliveryLock = new Object();
    private long generation;
    private int activeDeliveries;
    private boolean paused;
    private boolean stopped;

    @Inject
    public CloudTrailEventBridgeDelivery(EventBridgeService eventBridge) {
        this(eventBridge, new ThreadPoolExecutor(2, 2, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(256),
                Thread.ofPlatform().daemon().name("cloudtrail-eventbridge-", 0).factory(),
                new ThreadPoolExecutor.AbortPolicy()));
    }

    CloudTrailEventBridgeDelivery(EventBridgeService eventBridge, Executor deliveries) {
        this.eventBridge = eventBridge;
        this.deliveries = deliveries;
    }

    @PreDestroy
    void shutdown() {
        synchronized (deliveryLock) {
            stopped = true;
            paused = true;
            discardPending();
        }
        if (deliveries instanceof ExecutorService executorService) {
            executorService.shutdownNow();
        }
    }

    @Override
    public void beforeReset() {
        synchronized (deliveryLock) {
            paused = true;
            discardPending();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(RESET_DRAIN_TIMEOUT_SECONDS);
            while (activeDeliveries > 0) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) {
                    throw new IllegalStateException("CloudTrail event deliveries did not drain before reset");
                }
                try {
                    TimeUnit.NANOSECONDS.timedWait(deliveryLock, remaining);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("Interrupted while draining CloudTrail events before reset", e);
                }
            }
        }
    }

    @Override
    public void clear() {
        synchronized (deliveryLock) {
            discardPending();
        }
    }

    @Override
    public void afterReset() {
        synchronized (deliveryLock) {
            if (!stopped) {
                paused = false;
            }
        }
    }

    private void discardPending() {
        generation++;
        if (deliveries instanceof ThreadPoolExecutor executor) {
            executor.getQueue().clear();
        }
    }

    /** Queues {@code record}, a record a logging trail selected, for EventBridge's default bus. */
    public void deliver(ObjectNode record) {
        String eventName = record.path("eventName").asText();
        synchronized (deliveryLock) {
            if (paused || stopped) {
                LOG.warnv("Dropped the {0} event while delivery is {1}", eventName, stopped ? "stopped" : "resetting");
                return;
            }
            try {
                String source = source(record.path("eventSource").asText(""));
                String detailType = DETAIL_TYPES.get(record.path("eventType").asText(""));
                String detail = record.toString();
                if (source == null || detailType == null
                        || detail.getBytes(StandardCharsets.UTF_8).length > MAX_EVENT_BYTES) {
                    return;
                }
                queueEvent(eventName, source, detailType, detail, record.path("recipientAccountId").asText(),
                        record.path("awsRegion").asText());
            } catch (RuntimeException e) {
                // The call is already answered. A notification failure must not turn it into a failed one.
                LOG.warnv(e, "Failed to queue the {0} event", eventName);
            }
        }
    }

    /** {@code aws.<service>} for a record's {@code <service>.amazonaws.com}; null for any other source. */
    static String source(String eventSource) {
        return eventSource.endsWith(SERVICE_DOMAIN) && eventSource.length() > SERVICE_DOMAIN.length()
                ? "aws." + eventSource.substring(0, eventSource.length() - SERVICE_DOMAIN.length()) : null;
    }

    private void queueEvent(String eventName, String source, String detailType, String detail, String accountId,
                            String region) {
        long eventGeneration = generation;
        deliveries.execute(() -> {
            synchronized (deliveryLock) {
                if (paused || stopped || eventGeneration != generation) {
                    return;
                }
                activeDeliveries++;
            }
            try {
                RequestScopes.runAs(accountId, region, () -> eventBridge.publishServiceEvent(
                        source, detailType, detail, null, region));
            } catch (RuntimeException e) {
                LOG.warnv(e, "Failed to deliver the {0} event", eventName);
            } finally {
                synchronized (deliveryLock) {
                    activeDeliveries--;
                    deliveryLock.notifyAll();
                }
            }
        });
    }
}
