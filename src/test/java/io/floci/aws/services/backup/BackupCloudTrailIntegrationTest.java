package io.floci.aws.services.backup;

import com.fasterxml.jackson.databind.JsonNode;
import io.floci.aws.services.cloudtrail.CloudTrailLogWriter;
import io.floci.aws.testing.AwsTestClients;
import io.floci.aws.testing.CloudTrailLogFiles;
import io.floci.aws.testing.CloudTrailRequests;
import io.floci.aws.testing.EnforcementFixtures;
import io.floci.aws.testing.EnforcementFixtures.UserCredentials;
import io.floci.aws.testing.IamEnforcementProfile;
import io.floci.aws.testing.PartitionCleanup;
import io.floci.aws.testing.RestAssuredJsonUtils;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.backup.BackupClient;
import software.amazon.awssdk.services.backup.model.BackupException;
import software.amazon.awssdk.services.backup.model.BackupJobState;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The AWS Backup calls Floci serves reach a trail's log files under their own names, with their path, query and
 * body members, and without the tags.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class BackupCloudTrailIntegrationTest {

    private static final Region REGION = Region.US_EAST_1;
    private static final String SECRET = "do-not-log-" + UUID.randomUUID();
    /** The guide's StartBackupJob example: {@code "creationDate": "Jan 10, 2019 1:45:24 PM"}. */
    private static final String RECORD_TIMESTAMP = "[A-Z][a-z]{2} \\d{1,2}, \\d{4} \\d{1,2}:\\d{2}:\\d{2} [AP]M";

    @TestHTTPResource("/")
    static URI baseUri;

    @Inject
    CloudTrailLogWriter writer;

    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void vaultPlanAndRecoveryPointCallsAreRecordedUnderTheirNames() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-backup-logs-" + suffix;
        startTrail(account, "ct-backup-" + suffix, logs);
        String vault = "ct-vault-" + suffix;
        String role = "arn:aws:iam::" + account + ":role/backup";
        String resource = "arn:aws:dynamodb:us-east-1:" + account + ":table/ct-" + suffix;
        String policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\","
                + "\"Action\":\"backup:DeleteRecoveryPoint\",\"Resource\":\"*\"}]}";

        try (BackupClient backup = AwsTestClients.create(BackupClient.builder(), account, REGION, baseUri)) {
            String vaultArn = backup.createBackupVault(request -> request.backupVaultName(vault)
                    .backupVaultTags(Map.of("owner", SECRET))).backupVaultArn();
            backup.describeBackupVault(request -> request.backupVaultName(vault));
            backup.listBackupVaults(request -> request.maxResults(10));
            backup.putBackupVaultAccessPolicy(request -> request.backupVaultName(vault).policy(policy));
            backup.getBackupVaultAccessPolicy(request -> request.backupVaultName(vault));
            backup.deleteBackupVaultAccessPolicy(request -> request.backupVaultName(vault));
            backup.putBackupVaultLockConfiguration(request -> request.backupVaultName(vault).minRetentionDays(1L));
            backup.deleteBackupVaultLockConfiguration(request -> request.backupVaultName(vault));
            backup.tagResource(request -> request.resourceArn(vaultArn).tags(Map.of("team", SECRET)));
            backup.listTags(request -> request.resourceArn(vaultArn));
            backup.untagResource(request -> request.resourceArn(vaultArn).tagKeyList("team"));

            String plan = backup.createBackupPlan(request -> request
                    .backupPlan(body -> body.backupPlanName("ct-plan-" + suffix).rules(rule -> rule
                            .ruleName("daily").targetBackupVaultName(vault)
                            .scheduleExpression("cron(0 5 ? * * *)")))
                    .backupPlanTags(Map.of("owner", SECRET))).backupPlanId();
            String selection = backup.createBackupSelection(request -> request.backupPlanId(plan)
                    .backupSelection(body -> body.selectionName("ct-selection").iamRoleArn(role)
                            .resources(resource))).selectionId();
            backup.deleteBackupSelection(request -> request.backupPlanId(plan).selectionId(selection));
            backup.deleteBackupPlan(request -> request.backupPlanId(plan));

            String job = backup.startBackupJob(request -> request.backupVaultName(vault).resourceArn(resource)
                    .iamRoleArn(role)).backupJobId();
            await().atMost(Duration.ofSeconds(15)).pollInterval(Duration.ofMillis(100)).until(() ->
                    backup.describeBackupJob(request -> request.backupJobId(job)).state() == BackupJobState.COMPLETED);
            String point = backup.listRecoveryPointsByBackupVault(request -> request.backupVaultName(vault))
                    .recoveryPoints().getFirst().recoveryPointArn();
            backup.deleteRecoveryPoint(request -> request.backupVaultName(vault).recoveryPointArn(point));
            backup.deleteBackupVault(request -> request.backupVaultName(vault));
            assertThrows(BackupException.class, () -> backup.describeBackupVault(request -> request
                    .backupVaultName(vault)));

            List<JsonNode> records = backupRecords(account, logs);
            assertThat(records.toString(), not(containsString(SECRET)));

            JsonNode created = only(records, "CreateBackupVault");
            assertThat(created.path("eventSource").asText(), equalTo("backup.amazonaws.com"));
            assertThat(created.path("eventType").asText(), equalTo("AwsApiCall"));
            assertThat(created.path("readOnly").asBoolean(true), equalTo(false));
            assertThat(created.path("requestParameters").path("backupVaultName").asText(), equalTo(vault));
            assertThat(created.path("requestParameters").has("backupVaultTags"), equalTo(false));
            assertThat(created.path("responseElements").path("backupVaultArn").asText(), equalTo(vaultArn));
            assertThat(created.path("responseElements").path("creationDate").asText(), matchesPattern(RECORD_TIMESTAMP));

            JsonNode described = only(records, "DescribeBackupVault");
            assertThat(described.path("readOnly").asBoolean(), equalTo(true));
            assertThat(described.path("requestParameters").path("backupVaultName").asText(), equalTo(vault));
            assertThat(described.path("responseElements").isNull(), equalTo(true));
            assertThat(only(records, "ListBackupVaults").path("requestParameters").path("maxResults").asInt(),
                    equalTo(10));

            JsonNode policyPut = only(records, "PutBackupVaultAccessPolicy");
            assertThat(policyPut.path("readOnly").asBoolean(true), equalTo(false));
            assertThat(policyPut.path("requestParameters").path("policy").asText(), equalTo(policy));
            assertThat(policyPut.path("responseElements").isNull(), equalTo(true));
            assertThat(only(records, "GetBackupVaultAccessPolicy").path("readOnly").asBoolean(), equalTo(true));
            assertThat(only(records, "DeleteBackupVaultAccessPolicy").path("requestParameters")
                    .path("backupVaultName").asText(), equalTo(vault));

            assertThat(only(records, "PutBackupVaultLockConfiguration").path("requestParameters")
                    .path("minRetentionDays").asLong(), equalTo(1L));
            assertThat(only(records, "DeleteBackupVaultLockConfiguration").path("readOnly").asBoolean(true),
                    equalTo(false));

            JsonNode tagged = only(records, "TagResource");
            assertThat(tagged.path("requestParameters").path("resourceArn").asText(), equalTo(vaultArn));
            assertThat(tagged.path("requestParameters").has("tags"), equalTo(false));
            assertThat(only(records, "ListTags").path("requestParameters").path("resourceArn").asText(),
                    equalTo(vaultArn));
            assertThat(only(records, "UntagResource").path("requestParameters").has("tagKeyList"), equalTo(false));

            JsonNode planCreated = only(records, "CreateBackupPlan");
            assertThat(planCreated.path("requestParameters").path("backupPlan").path("rules").get(0)
                    .path("targetBackupVaultName").asText(), equalTo(vault));
            assertThat(planCreated.path("requestParameters").has("backupPlanTags"), equalTo(false));
            assertThat(planCreated.path("responseElements").path("backupPlanId").asText(), equalTo(plan));
            assertThat(only(records, "CreateBackupSelection").path("requestParameters").path("backupSelection")
                    .path("iamRoleArn").asText(), equalTo(role));
            JsonNode selectionDeleted = only(records, "DeleteBackupSelection").path("requestParameters");
            assertThat(selectionDeleted.path("backupPlanId").asText(), equalTo(plan));
            assertThat(selectionDeleted.path("selectionId").asText(), equalTo(selection));
            assertThat(only(records, "DeleteBackupPlan").path("requestParameters").path("backupPlanId").asText(),
                    equalTo(plan));

            JsonNode started = only(records, "StartBackupJob");
            assertThat(started.path("requestParameters").path("resourceArn").asText(), equalTo(resource));
            assertThat(started.path("requestParameters").path("iamRoleArn").asText(), equalTo(role));
            assertThat(started.path("responseElements").path("backupJobId").asText(), equalTo(job));
            assertThat(started.path("responseElements").path("creationDate").asText(), matchesPattern(RECORD_TIMESTAMP));

            JsonNode deletedPoint = only(records, "DeleteRecoveryPoint");
            assertThat(deletedPoint.path("readOnly").asBoolean(true), equalTo(false));
            assertThat(deletedPoint.path("requestParameters").path("backupVaultName").asText(), equalTo(vault));
            assertThat(deletedPoint.path("requestParameters").path("recoveryPointArn").asText(), equalTo(point));
            assertThat(deletedPoint.path("responseElements").isNull(), equalTo(true));
            assertThat(only(records, "ListRecoveryPointsByBackupVault").path("readOnly").asBoolean(), equalTo(true));

            JsonNode deletedVault = only(records, "DeleteBackupVault");
            assertThat(deletedVault.path("requestParameters").path("backupVaultName").asText(), equalTo(vault));
            assertThat(deletedVault.path("responseElements").isNull(), equalTo(true));

            JsonNode missing = records.stream().filter(record -> "DescribeBackupVault".equals(
                    record.path("eventName").asText()) && record.has("errorCode")).findFirst().orElseThrow();
            assertThat(missing.path("errorCode").asText(), equalTo("ResourceNotFoundException"));
            assertThat(missing.path("requestParameters").path("backupVaultName").asText(), equalTo(vault));
        }
    }

    @Test
    void aRefusedCallIsRecordedWithoutItsMembers() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-backup-logs-" + suffix;
        startTrail(account, "ct-backup-" + suffix, logs);
        String user = "ct-user-" + suffix;
        String vault = "ct-vault-" + suffix;
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, baseUri.getPort(),
                auth(account, "iam"), user);

        try (BackupClient backup = AwsTestClients.create(BackupClient.builder(), credentials.accessKeyId(),
                credentials.secretAccessKey(), REGION, baseUri)) {
            BackupException error = assertThrows(BackupException.class,
                    () -> backup.deleteBackupVault(request -> request.backupVaultName(vault)));
            assertThat(error.statusCode(), equalTo(403));
            assertThat(error.awsErrorDetails().errorCode(), equalTo("AccessDeniedException"));
        }

        JsonNode refused = only(backupRecords(account, logs), "DeleteBackupVault");
        assertThat(refused.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(refused.path("errorMessage").asText(), containsString("backup:DeleteBackupVault"));
        assertThat(refused.path("userIdentity").path("userName").asText(), equalTo(user));
        assertThat(refused.path("readOnly").asBoolean(true), equalTo(false));
        assertThat(refused.path("requestParameters").isNull(), equalTo(true));
        assertThat(refused.path("responseElements").isNull(), equalTo(true));
    }

    private static String account() {
        return "6615" + String.format("%08d", (int) (Math.random() * 100_000_000));
    }

    private void startTrail(String account, String trail, String bucket) {
        given().port(baseUri.getPort()).header("Authorization", auth(account, "s3"))
                .when().put("/" + bucket).then().statusCode(200);
        cleanup.register(() -> EnforcementFixtures.removeBucket(baseUri.getPort(), auth(account, "s3"), bucket));
        cloudTrail(account, "CreateTrail", "{\"Name\":\"" + trail + "\",\"S3BucketName\":\"" + bucket + "\"}");
        cleanup.register(() -> cloudTrail(account, "DeleteTrail", "{\"Name\":\"" + trail + "\"}"));
        cloudTrail(account, "StartLogging", "{\"Name\":\"" + trail + "\"}");
    }

    private static void cloudTrail(String account, String action, String body) {
        CloudTrailRequests.invokeCloudTrail(auth(account, "cloudtrail"), action, body).then().statusCode(200);
    }

    /** The AWS Backup records of {@code account}, read from the log files delivered to {@code bucket}. */
    private List<JsonNode> backupRecords(String account, String bucket) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(account, "s3")).stream()
                .filter(record -> "backup.amazonaws.com".equals(record.path("eventSource").asText()))
                .toList();
    }

    /** The one successful record of {@code eventName}, or its only record when none succeeded. */
    private static JsonNode only(List<JsonNode> records, String eventName) {
        List<JsonNode> found = records.stream()
                .filter(record -> eventName.equals(record.path("eventName").asText()) && !record.has("errorCode"))
                .toList();
        if (found.isEmpty()) {
            found = records.stream().filter(record -> eventName.equals(record.path("eventName").asText())).toList();
        }
        assertThat(eventName + " in " + records, found, hasSize(1));
        return found.getFirst();
    }
}
