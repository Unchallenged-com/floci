package io.floci.aws.services.secretsmanager;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.RequestScopes;
import io.floci.aws.core.common.Resettable;
import io.floci.aws.services.eventbridge.EventBridgeService;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Puts the CloudTrail record of a successful secret write on EventBridge's default bus, as
 * {@code AWS API Call via CloudTrail}, in the background so a slow target cannot hold the write.
 */
@ApplicationScoped
public class SecretsManagerEventPublisher implements Resettable {
    private static final Logger LOG = Logger.getLogger(SecretsManagerEventPublisher.class);
    private static final long RESET_DRAIN_TIMEOUT_SECONDS = 30;

    private final EventBridgeService eventBridge;
    private final Executor deliveries;
    private final Object deliveryLock = new Object();
    private long generation;
    private int activeDeliveries;
    private boolean paused;
    private boolean stopped;

    @Inject
    public SecretsManagerEventPublisher(EventBridgeService eventBridge) {
        this(eventBridge, new ThreadPoolExecutor(2, 2, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(256),
                Thread.ofPlatform().daemon().name("secret-event-publisher-", 0).factory(),
                new ThreadPoolExecutor.AbortPolicy()));
    }

    SecretsManagerEventPublisher(EventBridgeService eventBridge, Executor deliveries) {
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
                    throw new IllegalStateException("Secrets Manager event deliveries did not drain before reset");
                }
                try {
                    TimeUnit.NANOSECONDS.timedWait(deliveryLock, remaining);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("Interrupted while draining Secrets Manager events before reset", e);
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

    /** Queues {@code record}, the CloudTrail record of a successful {@code action}, for EventBridge. */
    public void secretWritten(String action, ObjectNode record) {
        synchronized (deliveryLock) {
            if (paused || stopped) {
                LOG.warnv("Dropped Secrets Manager {0} event while publisher is {1}",
                        action, stopped ? "stopped" : "resetting");
                return;
            }
            try {
                queueEvent(action, record, record.path("responseElements").path("arn").asText());
            } catch (RuntimeException e) {
                // The API write is already committed. Notification failures must not turn it into a failed write.
                LOG.warnv(e, "Failed to publish Secrets Manager {0} event", action);
            }
        }
    }

    private void queueEvent(String action, ObjectNode record, String secretArn) {
        String accountId = record.path("recipientAccountId").asText();
        String region = record.path("awsRegion").asText();
        String detail = record.toString();
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
                        "aws.secretsmanager", "AWS API Call via CloudTrail", detail, secretArn, region));
            } catch (RuntimeException e) {
                LOG.warnv(e, "Failed to deliver Secrets Manager {0} event", action);
            } finally {
                synchronized (deliveryLock) {
                    activeDeliveries--;
                    deliveryLock.notifyAll();
                }
            }
        });
    }
}
