package io.floci.aws.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.config.EmulatorConfig;
import io.floci.aws.core.common.AwsException;
import io.floci.aws.core.common.Resettable;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * CloudTrail's event history: "a viewable, searchable, downloadable, and immutable record of the
 * past 90 days of management events in an AWS Region", which "is separate from any trails or event
 * data stores that you create for your account. Changes you make to your event data stores or
 * trails do not affect the event history"
 * (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html).
 *
 * <p>Every management event Floci records is kept here, per account and Region, whatever the
 * trails, and {@code LookupEvents} reads it as its API Reference describes
 * (https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html): one lookup
 * attribute at most, a time range, the most recent event first, at most 50 events a page, and "two
 * per second, per account, per Region" ({@code lookup-events-per-second}). Events older than 90
 * days are dropped, and so is the oldest event once an account's Region holds
 * {@code event-history-max-events} of them, which bounds Floci's memory. The history is kept in
 * memory only.
 */
@ApplicationScoped
public class CloudTrailEventHistory implements Resettable {

    static final Duration RETENTION = Duration.ofDays(90);
    static final int MAX_PAGE = 50;
    static final Set<String> ATTRIBUTE_KEYS = Set.of("AccessKeyId", "EventId", "EventName", "EventSource",
            "ReadOnly", "ResourceName", "ResourceType", "Username");

    /** An event and the time it occurred, in epoch milliseconds. */
    record Entry(long time, ObjectNode record) {
    }

    /** One {@code LookupEvents} page: the events, most recent first, and the token of the next page, if any. */
    public record Page(List<ObjectNode> events, String nextToken) {
    }

    private final Map<String, Deque<Entry>> events = new ConcurrentHashMap<>();
    private final Map<String, Deque<Long>> lookups = new ConcurrentHashMap<>();
    private final int maxEvents;
    private final int lookupsPerSecond;
    private final Clock clock;

    @Inject
    public CloudTrailEventHistory(EmulatorConfig config) {
        this(config.services().cloudtrail().eventHistoryMaxEvents(),
                config.services().cloudtrail().lookupEventsPerSecond(), Clock.systemUTC());
    }

    /**
     * @param maxEvents        the events kept per account and Region
     * @param lookupsPerSecond the {@code LookupEvents} requests allowed per second per account and
     *                         Region; 0 for no limit
     */
    CloudTrailEventHistory(int maxEvents, int lookupsPerSecond, Clock clock) {
        this.maxEvents = Math.max(1, maxEvents);
        this.lookupsPerSecond = Math.max(0, lookupsPerSecond);
        this.clock = clock;
    }

    /** Keeps {@code record}, a management event of {@code accountId} in {@code region}. */
    public void add(String accountId, String region, ObjectNode record) {
        long time = eventTime(record);
        Deque<Entry> history = events.computeIfAbsent(key(accountId, region), ignored -> new ArrayDeque<>());
        synchronized (history) {
            history.addLast(new Entry(time, record.deepCopy()));
            while (history.size() > maxEvents) {
                history.removeFirst();
            }
        }
    }

    /**
     * The page of events of {@code accountId} in {@code region} that match {@code attribute} (null
     * for every event) and occurred within {@code [start, end]} (either null for no bound), from
     * {@code nextToken} (null for the first page).
     */
    public Page lookup(String accountId, String region, LookupAttribute attribute, Instant start, Instant end,
                       int maxResults, String nextToken) {
        throttle(key(accountId, region));
        if (start != null && end != null && start.isAfter(end)) {
            throw new AwsException("InvalidTimeRangeException",
                    "Start time must be before or equal to end time.", 400);
        }
        String query = attribute + "|" + start + "|" + end;
        int offset = nextToken == null ? 0 : offset(nextToken, query);
        long oldest = clock.millis() - RETENTION.toMillis();
        List<ObjectNode> matching = new ArrayList<>();
        Deque<Entry> history = events.get(key(accountId, region));
        if (history != null) {
            synchronized (history) {
                history.removeIf(entry -> entry.time() < oldest);
                Iterator<Entry> newestFirst = history.descendingIterator();
                while (newestFirst.hasNext()) {
                    Entry entry = newestFirst.next();
                    if ((start == null || entry.time() >= start.toEpochMilli())
                            && (end == null || entry.time() <= end.toEpochMilli())
                            && (attribute == null || attribute.matches(entry.record()))) {
                        matching.add(entry.record());
                    }
                }
            }
        }
        int size = Math.min(Math.max(1, maxResults), MAX_PAGE);
        int to = Math.min(matching.size(), offset + size);
        List<ObjectNode> page = offset >= matching.size() ? List.of() : List.copyOf(matching.subList(offset, to));
        return new Page(page, to < matching.size() ? token(to, query) : null);
    }

    @Override
    public void clear() {
        events.clear();
        lookups.clear();
    }

    private void throttle(String key) {
        if (lookupsPerSecond == 0) {
            return;
        }
        long now = clock.millis();
        Deque<Long> recent = lookups.computeIfAbsent(key, ignored -> new ArrayDeque<>());
        synchronized (recent) {
            while (!recent.isEmpty() && recent.peekFirst() <= now - 1000) {
                recent.removeFirst();
            }
            if (recent.size() >= lookupsPerSecond) {
                throw new AwsException("ThrottlingException", "Rate exceeded", 400);
            }
            recent.addLast(now);
        }
    }

    private static String token(int offset, String query) {
        String raw = offset + ":" + Integer.toHexString(query.hashCode());
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }

    /** The offset {@code token} resumes from; refused when it is not one this lookup's parameters gave. */
    private static int offset(String token, String query) {
        try {
            String raw = new String(Base64.getUrlDecoder().decode(token), StandardCharsets.UTF_8);
            int colon = raw.indexOf(':');
            if (colon > 0 && raw.substring(colon + 1).equals(Integer.toHexString(query.hashCode()))) {
                return Integer.parseInt(raw.substring(0, colon));
            }
        } catch (IllegalArgumentException invalid) {
            // Not a token Floci gave: refused below.
        }
        throw new AwsException("InvalidNextTokenException", "Invalid NextToken.", 400);
    }

    private long eventTime(ObjectNode record) {
        try {
            return Instant.parse(record.path("eventTime").asText()).toEpochMilli();
        } catch (RuntimeException unparsable) {
            return clock.millis();
        }
    }

    private static String key(String accountId, String region) {
        return accountId + "|" + region;
    }

    /** One {@code LookupAttribute}: an {@link #ATTRIBUTE_KEYS} key and the value an event must carry for it. */
    public record LookupAttribute(String key, String value) {

        public LookupAttribute {
            if (key == null || !ATTRIBUTE_KEYS.contains(key)) {
                throw new AwsException("InvalidLookupAttributesException",
                        "Invalid lookup attribute key: " + key, 400);
            }
            if (value == null || value.isEmpty()) {
                throw new AwsException("InvalidLookupAttributesException",
                        "Lookup attribute value must not be empty.", 400);
            }
        }

        boolean matches(ObjectNode record) {
            return switch (key) {
                case "AccessKeyId" -> value.equals(LookupFields.accessKeyId(record));
                case "EventId" -> value.equals(record.path("eventID").asText());
                case "EventName" -> value.equals(record.path("eventName").asText());
                case "EventSource" -> value.equals(record.path("eventSource").asText());
                case "ReadOnly" -> value.equals(record.path("readOnly").asText());
                case "Username" -> value.equals(LookupFields.username(record));
                case "ResourceType" -> anyResource(record, false);
                case "ResourceName" -> anyResource(record, true);
                default -> false;
            };
        }

        private boolean anyResource(ObjectNode record, boolean byName) {
            for (JsonNode resource : record.path("resources")) {
                String field = byName ? LookupFields.resourceName(resource) : resource.path("type").asText();
                if (value.equals(field)) {
                    return true;
                }
            }
            return false;
        }
    }
}
