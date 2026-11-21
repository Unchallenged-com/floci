package io.floci.aws.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.time.Instant;

/**
 * A recorded event as {@code LookupEvents} answers it: the {@code Event} shape of the CloudTrail
 * API Reference (https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_Event.html),
 * read from the record.
 *
 * <p>{@code Username} is "A user name or role name of the requester": {@code root} for the account's
 * own credentials and an IAM user's name, as the CloudTrail User Guide's lookup examples show
 * ({@code "Username": "root"}), and a role session's name, as the AWS CLI's {@code lookup-events}
 * example shows ({@code "Username": "my-session-name"} for {@code assumed-role/my-role/my-session-name}).
 * {@code Resources} are the record's {@code resources}, each its type and its name: the name the
 * CloudTrail documentation shows for its type, else its ARN ({@link #resourceName}).
 */
final class LookupFields {

    private LookupFields() {
    }

    static ObjectNode event(ObjectMapper mapper, ObjectNode record) {
        ObjectNode event = mapper.createObjectNode();
        event.put("EventId", record.path("eventID").asText());
        event.put("EventName", record.path("eventName").asText());
        event.put("ReadOnly", record.path("readOnly").asText());
        String accessKeyId = accessKeyId(record);
        if (accessKeyId != null) {
            event.put("AccessKeyId", accessKeyId);
        }
        event.put("EventTime", Instant.parse(record.path("eventTime").asText()).getEpochSecond());
        event.put("EventSource", record.path("eventSource").asText());
        String username = username(record);
        if (username != null) {
            event.put("Username", username);
        }
        ArrayNode resources = event.putArray("Resources");
        for (JsonNode resource : record.path("resources")) {
            ObjectNode entry = resources.addObject();
            entry.put("ResourceType", resource.path("type").asText(null));
            entry.put("ResourceName", resourceName(resource));
        }
        event.put("CloudTrailEvent", record.toString());
        return event;
    }

    /**
     * The name event history gives a record's resource. Where the CloudTrail documentation shows
     * the name of a type, it is that name: a role's name, as the User Guide's lookup by
     * {@code ResourceName} shows ({@code CloudTrail_CloudWatchLogs_Role},
     * https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events-cli.html), an
     * instance's ID and an Auto Scaling group's name, as the API Reference's {@code Resource} shape
     * shows them ("auto-scaling-test-group", "i-1234567",
     * https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_Resource.html). Any other
     * resource is named by its ARN, as a KMS key is: "Key ARN (or key ID and key ARN)"
     * (https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html).
     */
    static String resourceName(JsonNode resource) {
        String arn = resource.path("ARN").asText(null);
        if (arn == null) {
            return null;
        }
        return switch (resource.path("type").asText("")) {
            case "AWS::IAM::Role", "AWS::EC2::Instance" -> arn.substring(arn.lastIndexOf('/') + 1);
            case "AWS::AutoScaling::AutoScalingGroup" -> {
                int name = arn.indexOf(":autoScalingGroupName/");
                yield name < 0 ? arn : arn.substring(name + ":autoScalingGroupName/".length());
            }
            default -> arn;
        };
    }

    static String accessKeyId(ObjectNode record) {
        String accessKeyId = record.path("userIdentity").path("accessKeyId").asText("");
        return accessKeyId.isEmpty() ? null : accessKeyId;
    }

    static String username(ObjectNode record) {
        JsonNode identity = record.path("userIdentity");
        String type = identity.path("type").asText();
        String arn = identity.path("arn").asText("");
        return switch (type) {
            case "Root" -> "root";
            case "AssumedRole" -> arn.isEmpty() ? null : arn.substring(arn.lastIndexOf('/') + 1);
            default -> identity.path("userName").asText(null);
        };
    }
}
