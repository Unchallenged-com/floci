package io.floci.aws.services.cloudtrail;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AwsArnUtils;
import io.floci.aws.core.common.AwsException;
import io.floci.aws.core.common.RequestScopes;
import io.floci.aws.core.common.ServiceCallAuthorizer;
import io.floci.aws.core.common.ServicePrincipals;
import io.floci.aws.services.cloudtrail.model.Trail;
import io.floci.aws.services.cloudwatch.logs.CloudWatchLogsService;
import io.floci.aws.services.iam.IamPolicyEvaluator;
import io.floci.aws.services.iam.ServiceRoleAuthorizer;
import io.floci.aws.services.sns.SnsService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Where a trail sends a log file besides its S3 bucket: its CloudWatch Logs log group and its SNS topic.
 *
 * <p>CloudWatch Logs (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html):
 * each record the file holds is one event of the log group the trail names, in the stream "{@code account_ID}_CloudTrail_
 * {@code trail_region}" (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-log-group-log-stream-naming-for-cloudtrail.html),
 * which a multi-Region trail's records from every Region share, as the role's policy grants
 * {@code logs:CreateLogStream} and {@code logs:PutLogEvents} on that stream alone
 * (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-required-policy-for-cloudwatch-logs.html).
 * The event's message is the record, and its timestamp the time of delivery: "The Time (UTC) column in the
 * CloudWatch console shows when the event was delivered to your log group. To see the actual time that the event was
 * logged by CloudTrail, see the {@code eventTime} field." CloudTrail writes them as the role the trail names, so with
 * IAM enforcement on, the role must trust {@code cloudtrail.amazonaws.com} and allow both actions on the stream. A
 * record over 256 KB is not sent: "CloudTrail does not send these events to CloudWatch Logs or EventBridge".
 *
 * <p>SNS (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/configure-sns-notifications-for-cloudtrail.html):
 * "CloudTrail sends a notification when log files are written to the Amazon S3 bucket", whose {@code Message} is
 * {@code {"s3Bucket": ..., "s3ObjectKey": [...]}}, one notification for each log file. With IAM enforcement on, the
 * topic's policy must allow {@code cloudtrail.amazonaws.com} to publish
 * (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-permissions-for-sns-notifications.html).
 *
 * <p>Each delivery's time, or its error, is the trail's {@code GetTrailStatus}
 * ({@code LatestCloudWatchLogsDeliveryTime}, {@code LatestNotificationTime} and their errors).
 */
@ApplicationScoped
public class CloudTrailLogDestinations {

    private static final Logger LOG = Logger.getLogger(CloudTrailLogDestinations.class);
    private static final String SERVICE = "cloudtrail";
    /** The largest event CloudTrail sends to CloudWatch Logs. */
    static final int MAX_EVENT_BYTES = 256 * 1024;

    private final CloudTrailService cloudTrail;
    private final CloudWatchLogsService logs;
    private final SnsService sns;
    private final ServiceRoleAuthorizer roles;
    private final ServiceCallAuthorizer serviceCalls;
    private final ObjectMapper mapper;

    @Inject
    public CloudTrailLogDestinations(CloudTrailService cloudTrail, CloudWatchLogsService logs, SnsService sns,
                                     ServiceRoleAuthorizer roles, ServiceCallAuthorizer serviceCalls,
                                     ObjectMapper mapper) {
        this.cloudTrail = cloudTrail;
        this.logs = logs;
        this.sns = sns;
        this.roles = roles;
        this.serviceCalls = serviceCalls;
        this.mapper = mapper;
    }

    /**
     * Sends the log file {@code objectKey}, holding {@code records}, that {@code trail} just wrote to its bucket, to
     * its log group and its topic, the ones it names. A destination that refuses or fails is reported in the trail's
     * status and does not stop the other.
     */
    public void delivered(CloudTrailService.TrailKey key, Trail trail, List<ObjectNode> records, String objectKey) {
        if (trail.cloudWatchLogsLogGroupArn() != null && trail.cloudWatchLogsRoleArn() != null) {
            String error = toLogGroup(key, trail, records);
            cloudTrail.recordCloudWatchLogsDelivery(key, System.currentTimeMillis(), error);
        }
        if (trail.snsTopicArn() != null) {
            String error = toTopic(key, trail, objectKey);
            cloudTrail.recordNotification(key, System.currentTimeMillis(), error);
        }
    }

    /** Writes each record as one event of the trail's log group; the error that stopped it, or null. */
    private String toLogGroup(CloudTrailService.TrailKey key, Trail trail, List<ObjectNode> records) {
        String groupArn = trail.cloudWatchLogsLogGroupArn();
        try {
            AwsArnUtils.Arn group = AwsArnUtils.parse(groupArn);
            String groupName = groupName(group.resource());
            String stream = key.accountId() + "_CloudTrail_" + key.region();
            String streamArn = new AwsArnUtils.Arn(group.partition(), "logs", group.region(), group.accountId(),
                    "log-group:" + groupName + ":log-stream:" + stream).toString();
            String refusal = roles.refusal(trail.cloudWatchLogsRoleArn(), key.accountId(),
                    ServicePrincipals.of(SERVICE), trail.trailArn(), List.of(
                            new ServiceRoleAuthorizer.Permission("logs:CreateLogStream", streamArn),
                            new ServiceRoleAuthorizer.Permission("logs:PutLogEvents", streamArn))).orElse(null);
            if (refusal != null) {
                return "AccessDeniedException: " + refusal;
            }
            long now = System.currentTimeMillis();
            List<Map<String, Object>> events = new ArrayList<>();
            for (ObjectNode record : records) {
                String message = mapper.writeValueAsString(record);
                if (message.getBytes(StandardCharsets.UTF_8).length <= MAX_EVENT_BYTES) {
                    Map<String, Object> event = new LinkedHashMap<>();
                    event.put("timestamp", now);
                    event.put("message", message);
                    events.add(event);
                }
            }
            if (events.isEmpty()) {
                return null;
            }
            ensureStream(group.accountId(), groupName, stream, group.region());
            logs.putLogEventsForAccount(group.accountId(), groupName, stream, events, group.region());
            return null;
        } catch (AwsException e) {
            return error(e);
        } catch (IllegalArgumentException | JsonProcessingException e) {
            LOG.warnv(e, "CloudTrail could not deliver to log group {0}", groupArn);
            return e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage());
        }
    }

    private void ensureStream(String accountId, String groupName, String stream, String region) {
        try {
            logs.createLogStreamForAccount(accountId, groupName, stream, region);
        } catch (AwsException e) {
            if (!"ResourceAlreadyExistsException".equals(e.getErrorCode())) {
                throw e;
            }
        }
    }

    /** Publishes the notification of {@code objectKey}; the error that stopped it, or null. */
    private String toTopic(CloudTrailService.TrailKey key, Trail trail, String objectKey) {
        String topicArn = topicArn(trail.snsTopicArn(), key);
        try {
            AwsArnUtils.Arn topic = AwsArnUtils.parse(topicArn);
            if (serviceCalls.authorize(SERVICE, "sns:Publish", topicArn, trail.trailArn(), key.accountId())
                    != IamPolicyEvaluator.Decision.ALLOW) {
                return "AuthorizationError: CloudTrail is not authorized to publish to " + topicArn;
            }
            ObjectNode message = mapper.createObjectNode().put("s3Bucket", trail.s3BucketName());
            message.putArray("s3ObjectKey").add(objectKey);
            String body = mapper.writeValueAsString(message);
            RequestScopes.callAsChecked(topic.accountId(), topic.region(), () -> sns.publish(topicArn, null, body,
                    null, topic.region()));
            return null;
        } catch (AwsException e) {
            return error(e);
        } catch (Exception e) {
            LOG.warnv(e, "CloudTrail could not notify topic {0}", topicArn);
            return e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage());
        }
    }

    /**
     * The topic a trail names: "You can specify the name or the ARN for the Amazon SNS topic", a name being the
     * trail's account's topic in the trail's Region.
     */
    static String topicArn(String named, CloudTrailService.TrailKey key) {
        return AwsArnUtils.isArn(named) ? named
                : AwsArnUtils.Arn.of("sns", key.region(), key.accountId(), named).toString();
    }

    /** The log group's name in its ARN's resource, {@code log-group:<name>} or {@code log-group:<name>:*}. */
    static String groupName(String resource) {
        String name = resource.startsWith("log-group:") ? resource.substring("log-group:".length()) : resource;
        return name.endsWith(":*") ? name.substring(0, name.length() - 2) : name;
    }

    private static String error(AwsException e) {
        return e.getErrorCode() + (e.getMessage() == null ? "" : ": " + e.getMessage());
    }
}
