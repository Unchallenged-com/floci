package io.floci.aws.services.backup;

import io.floci.aws.testing.AwsTestClients;
import io.floci.aws.testing.EnforcementFixtures;
import io.floci.aws.testing.EnforcementFixtures.UserCredentials;
import io.floci.aws.testing.IamEnforcementProfile;
import io.floci.aws.testing.PartitionCleanup;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.function.Executable;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.backup.BackupClient;
import software.amazon.awssdk.services.backup.model.BackupException;
import software.amazon.awssdk.services.backup.model.BackupJobState;
import software.amazon.awssdk.services.backup.model.RecoveryPointByBackupVault;
import software.amazon.awssdk.services.backup.model.ResourceNotFoundException;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Under IAM enforcement an AWS Backup call is checked as the action AWS's Service Reference gives its operation, on
 * the resource its request names, with the tags the resource holds and the tags the request carries, and a refused
 * call is answered as AWS Backup answers it: {@code AccessDeniedException}, HTTP 403.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class BackupIamEnforcementIntegrationTest {

    private static final Region REGION = Region.US_EAST_1;

    @TestHTTPResource("/")
    URI baseUri;

    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @Test
    void aCallerWithoutAGrantIsRefusedAsAwsBackupRefuses() {
        String account = account();
        String vault = "iam-vault-" + suffix();
        UserCredentials user = user(account, null);

        try (BackupClient backup = as(user); BackupClient root = root(account)) {
            refused(() -> backup.listBackupVaults(request -> request.maxResults(10)), "backup:ListBackupVaults");
            refused(() -> backup.createBackupVault(request -> request.backupVaultName(vault)),
                    "backup:CreateBackupVault");
            refused(() -> backup.listBackupPlans(request -> request.maxResults(10)), "backup:ListBackupPlans");
            assertThrows(ResourceNotFoundException.class,
                    () -> root.describeBackupVault(request -> request.backupVaultName(vault)));
        }
    }

    @Test
    void anExplicitDenyKeepsTheRecoveryPointTheVaultAndItsLock() {
        String account = account();
        String vault = "iam-vault-" + suffix();
        UserCredentials user = user(account, statement("Allow", "\"backup:*\"", "*")
                + "," + statement("Deny", "[\"backup:DeleteRecoveryPoint\",\"backup:DeleteBackupVault\","
                + "\"backup:DeleteBackupVaultLockConfiguration\",\"backup:PutBackupVaultAccessPolicy\"]", "*"));

        try (BackupClient root = root(account); BackupClient backup = as(user)) {
            String point = recoveryPoint(root, account, vault);
            root.putBackupVaultLockConfiguration(request -> request.backupVaultName(vault).maxRetentionDays(365L));

            refused(() -> backup.deleteRecoveryPoint(request -> request.backupVaultName(vault)
                    .recoveryPointArn(point)), "backup:DeleteRecoveryPoint");
            refused(() -> backup.deleteBackupVaultLockConfiguration(request -> request.backupVaultName(vault)),
                    "backup:DeleteBackupVaultLockConfiguration");
            refused(() -> backup.putBackupVaultAccessPolicy(request -> request.backupVaultName(vault)
                    .policy("{\"Version\":\"2012-10-17\",\"Statement\":[]}")), "backup:PutBackupVaultAccessPolicy");
            refused(() -> backup.deleteBackupVault(request -> request.backupVaultName(vault)),
                    "backup:DeleteBackupVault");

            assertThat(backup.listRecoveryPointsByBackupVault(request -> request.backupVaultName(vault))
                    .recoveryPoints(), hasSize(1));
            assertThat(backup.describeBackupVault(request -> request.backupVaultName(vault)).maxRetentionDays(),
                    equalTo(365L));
        }
    }

    @Test
    void aGrantOnOneVaultDoesNotReachAnother() {
        String account = account();
        String granted = "iam-granted-" + suffix();
        String other = "iam-other-" + suffix();

        try (BackupClient root = root(account)) {
            String grantedArn = vault(account, root, granted, Map.of());
            vault(account, root, other, Map.of());
            UserCredentials user = user(account, statement("Allow",
                    "[\"backup:DescribeBackupVault\",\"backup:DeleteBackupVault\"]", grantedArn));
            try (BackupClient backup = as(user)) {
                refused(() -> backup.describeBackupVault(request -> request.backupVaultName(other)),
                        "backup:DescribeBackupVault");
                refused(() -> backup.deleteBackupVault(request -> request.backupVaultName(other)),
                        "backup:DeleteBackupVault");
                backup.describeBackupVault(request -> request.backupVaultName(granted));
                backup.deleteBackupVault(request -> request.backupVaultName(granted));
            }
            root.describeBackupVault(request -> request.backupVaultName(other));
        }
    }

    @Test
    void aGrantOnOneRecoveryPointDoesNotReachAnother() {
        String account = account();
        String vault = "iam-vault-" + suffix();

        try (BackupClient root = root(account)) {
            String kept = recoveryPoint(root, account, vault);
            String deleted = recoveryPoint(root, account, vault);
            UserCredentials user = user(account, statement("Allow", "\"backup:DeleteRecoveryPoint\"", deleted));
            try (BackupClient backup = as(user)) {
                refused(() -> backup.deleteRecoveryPoint(request -> request.backupVaultName(vault)
                        .recoveryPointArn(kept)), "backup:DeleteRecoveryPoint");
                backup.deleteRecoveryPoint(request -> request.backupVaultName(vault).recoveryPointArn(deleted));
            }
            assertThat(root.listRecoveryPointsByBackupVault(request -> request.backupVaultName(vault))
                    .recoveryPoints().stream().map(RecoveryPointByBackupVault::recoveryPointArn).toList(),
                    equalTo(List.of(kept)));
        }
    }

    @Test
    void aResourceTagConditionReadsTheTagsOfTheVaultAndThePlan() {
        String account = account();
        String guarded = "iam-guarded-" + suffix();
        String open = "iam-open-" + suffix();
        String deny = "{\"Effect\":\"Deny\",\"Action\":[\"backup:DeleteBackupVault\",\"backup:DeleteBackupPlan\"],"
                + "\"Resource\":\"*\",\"Condition\":{\"StringEquals\":{\"aws:ResourceTag/protected\":\"true\"}}}";

        try (BackupClient root = root(account)) {
            vault(account, root, guarded, Map.of("protected", "true"));
            vault(account, root, open, Map.of("protected", "false"));
            String guardedPlan = plan(account, root, guarded, Map.of("protected", "true"));
            UserCredentials user = user(account, statement("Allow", "\"backup:*\"", "*") + "," + deny);
            try (BackupClient backup = as(user)) {
                refused(() -> backup.deleteBackupPlan(request -> request.backupPlanId(guardedPlan)),
                        "backup:DeleteBackupPlan");
                refused(() -> backup.deleteBackupVault(request -> request.backupVaultName(guarded)),
                        "backup:DeleteBackupVault");
                backup.deleteBackupVault(request -> request.backupVaultName(open));
            }
        }
    }

    @Test
    void aRequestTagConditionReadsTheTagsACreateCarries() {
        String account = account();
        String untagged = "iam-untagged-" + suffix();
        String tagged = "iam-tagged-" + suffix();
        UserCredentials user = user(account, "{\"Effect\":\"Allow\",\"Action\":\"backup:CreateBackupVault\","
                + "\"Resource\":\"*\",\"Condition\":{\"StringEquals\":{\"aws:RequestTag/owner\":\"ops\"}}},"
                + statement("Allow", "\"backup:TagResource\"", "*"));

        try (BackupClient backup = as(user)) {
            refused(() -> backup.createBackupVault(request -> request.backupVaultName(untagged)),
                    "backup:CreateBackupVault");
            backup.createBackupVault(request -> request.backupVaultName(tagged)
                    .backupVaultTags(Map.of("owner", "ops")));
            afterwards(account, client -> client.deleteBackupVault(request -> request.backupVaultName(tagged)));
        }
    }

    @Test
    void aCreateCarryingTagsAlsoNeedsTagResource() {
        String account = account();
        String vault = "iam-vault-" + suffix();
        UserCredentials user = user(account, statement("Allow", "\"backup:CreateBackupVault\"", "*"));

        try (BackupClient backup = as(user); BackupClient root = root(account)) {
            refused(() -> backup.createBackupVault(request -> request.backupVaultName(vault)
                    .backupVaultTags(Map.of("owner", "ops"))), "backup:TagResource");
            assertThrows(ResourceNotFoundException.class,
                    () -> root.describeBackupVault(request -> request.backupVaultName(vault)));
            backup.createBackupVault(request -> request.backupVaultName(vault));
            afterwards(account, client -> client.deleteBackupVault(request -> request.backupVaultName(vault)));
        }
    }

    @Test
    void aRetentionConditionReadsTheLockTheRequestSets() {
        String account = account();
        String vault = "iam-vault-" + suffix();
        String deny = "{\"Effect\":\"Deny\",\"Action\":\"backup:PutBackupVaultLockConfiguration\",\"Resource\":\"*\","
                + "\"Condition\":{\"NumericLessThan\":{\"backup:MinRetentionDays\":\"7\"}}}";

        try (BackupClient root = root(account)) {
            vault(account, root, vault, Map.of());
            UserCredentials user = user(account, statement("Allow", "\"backup:*\"", "*") + "," + deny);
            try (BackupClient backup = as(user)) {
                refused(() -> backup.putBackupVaultLockConfiguration(request -> request.backupVaultName(vault)
                        .minRetentionDays(1L)), "backup:PutBackupVaultLockConfiguration");
                backup.putBackupVaultLockConfiguration(request -> request.backupVaultName(vault)
                        .minRetentionDays(30L));
            }
            assertThat(root.describeBackupVault(request -> request.backupVaultName(vault)).minRetentionDays(),
                    equalTo(30L));
        }
    }

    @Test
    void theTagRoutesAreCheckedAsTheirOwnActions() {
        String account = account();
        String vault = "iam-vault-" + suffix();

        try (BackupClient root = root(account)) {
            String arn = vault(account, root, vault, Map.of("team", "ops"));
            UserCredentials user = user(account, statement("Allow", "\"backup:ListTags\"", arn));
            try (BackupClient backup = as(user)) {
                assertThat(backup.listTags(request -> request.resourceArn(arn)).tags(),
                        equalTo(Map.of("team", "ops")));
                refused(() -> backup.tagResource(request -> request.resourceArn(arn).tags(Map.of("team", "x"))),
                        "backup:TagResource");
                refused(() -> backup.untagResource(request -> request.resourceArn(arn).tagKeyList("team")),
                        "backup:UntagResource");
            }
            assertThat(root.listTags(request -> request.resourceArn(arn)).tags(), equalTo(Map.of("team", "ops")));
        }
    }

    /** Asserts {@code call} is refused as AWS Backup refuses a caller lacking {@code action}. */
    private static void refused(Executable call, String action) {
        BackupException error = assertThrows(BackupException.class, call);
        assertThat(error.statusCode(), equalTo(403));
        assertThat(error.awsErrorDetails().errorCode(), equalTo("AccessDeniedException"));
        assertThat(error.awsErrorDetails().errorMessage(), containsString(action));
    }

    /** A vault named {@code name} with {@code tags}, deleted afterwards, and its ARN. */
    private String vault(String account, BackupClient root, String name, Map<String, String> tags) {
        String arn = root.createBackupVault(request -> request.backupVaultName(name).backupVaultTags(tags))
                .backupVaultArn();
        afterwards(account, client -> {
            try {
                client.deleteBackupVault(request -> request.backupVaultName(name));
            } catch (ResourceNotFoundException alreadyDeleted) {
                // The test deleted it.
            }
        });
        return arn;
    }

    /** A plan backing up to {@code vault}, with {@code tags}, deleted afterwards, and its id. */
    private String plan(String account, BackupClient root, String vault, Map<String, String> tags) {
        String id = root.createBackupPlan(request -> request.backupPlan(body -> body
                .backupPlanName("iam-plan-" + suffix()).rules(rule -> rule.ruleName("daily")
                        .targetBackupVaultName(vault).scheduleExpression("cron(0 5 ? * * *)")))
                .backupPlanTags(tags)).backupPlanId();
        afterwards(account, client -> client.deleteBackupPlan(request -> request.backupPlanId(id)));
        return id;
    }

    /**
     * A completed recovery point in {@code vault}, created with the vault on first use; the recovery points go with the
     * vault, which is deleted afterwards.
     */
    private String recoveryPoint(BackupClient root, String account, String vault) {
        boolean exists;
        try {
            root.describeBackupVault(request -> request.backupVaultName(vault));
            exists = true;
        } catch (ResourceNotFoundException missing) {
            exists = false;
        }
        if (!exists) {
            vault(account, root, vault, Map.of());
            afterwards(account, client -> client.listRecoveryPointsByBackupVault(request -> request
                    .backupVaultName(vault)).recoveryPoints().forEach(point -> client.deleteRecoveryPoint(request ->
                            request.backupVaultName(vault).recoveryPointArn(point.recoveryPointArn()))));
        }
        String job = root.startBackupJob(request -> request.backupVaultName(vault)
                .resourceArn("arn:aws:dynamodb:us-east-1:" + account + ":table/iam-" + suffix())
                .iamRoleArn("arn:aws:iam::" + account + ":role/backup")).backupJobId();
        await().atMost(Duration.ofSeconds(15)).pollInterval(Duration.ofMillis(100)).until(() ->
                root.describeBackupJob(request -> request.backupJobId(job)).state() == BackupJobState.COMPLETED);
        return root.describeBackupJob(request -> request.backupJobId(job)).recoveryPointArn();
    }

    /** Runs {@code action} as {@code account}'s root after the test, with a client of its own. */
    private void afterwards(String account, Consumer<BackupClient> action) {
        cleanup.register(() -> {
            try (BackupClient client = root(account)) {
                action.accept(client);
            }
        });
    }

    /** An IAM user of {@code account} holding {@code statements} inline, or nothing; removed afterwards. */
    private UserCredentials user(String account, String statements) {
        String name = "iam-backup-" + suffix();
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, baseUri.getPort(),
                auth(account, "iam"), name);
        if (statements != null) {
            EnforcementFixtures.putUserPolicy(baseUri.getPort(), auth(account, "iam"), name, "backup",
                    "{\"Version\":\"2012-10-17\",\"Statement\":[" + statements + "]}");
        }
        return credentials;
    }

    private static String statement(String effect, String actions, String resource) {
        return "{\"Effect\":\"" + effect + "\",\"Action\":" + actions + ",\"Resource\":\"" + resource + "\"}";
    }

    private BackupClient as(UserCredentials user) {
        return AwsTestClients.create(BackupClient.builder(), user.accessKeyId(), user.secretAccessKey(), REGION,
                baseUri);
    }

    private BackupClient root(String account) {
        return AwsTestClients.create(BackupClient.builder(), account, REGION, baseUri);
    }

    private static String account() {
        return "6616" + String.format("%08d", (int) (Math.random() * 100_000_000));
    }

    private static String suffix() {
        return UUID.randomUUID().toString().substring(0, 8);
    }
}
