package io.floci.aws.services.eventbridge.model;

import io.quarkus.runtime.annotations.RegisterForReflection;

/**
 * A rule's state. "Enable the rule so that EventBridge matches events against the rule, except for read-only AWS
 * management events delivered through CloudTrail", or with {@code ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS},
 * "Enable the rule so that EventBridge matches all events against the rule, including read-only management events
 * delivered through CloudTrail"
 * (https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event-cloudtrail-management.html).
 */
@RegisterForReflection
public enum RuleState {
    ENABLED,
    DISABLED,
    ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS;

    /** Whether the rule matches events, and fires on its schedule. */
    public boolean isEnabled() {
        return this != DISABLED;
    }

    /** Whether the rule matches an event, which {@code readOnlyCloudTrailManagementEvent} says it is or not. */
    public boolean matches(boolean readOnlyCloudTrailManagementEvent) {
        return this == ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS
                || this == ENABLED && !readOnlyCloudTrailManagementEvent;
    }

    /** The state a request names, {@code ENABLED} when it names none or one this enum does not hold. */
    public static RuleState named(String state) {
        if (state == null || state.isBlank()) {
            return ENABLED;
        }
        for (RuleState value : values()) {
            if (value.name().equalsIgnoreCase(state)) {
                return value;
            }
        }
        return ENABLED;
    }
}
