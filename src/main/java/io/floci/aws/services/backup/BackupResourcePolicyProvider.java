package io.floci.aws.services.backup;

import io.floci.aws.core.common.AwsArnUtils;
import io.floci.aws.core.common.RegionResolver;
import io.floci.aws.services.iam.ResourcePolicyProvider;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.List;
import java.util.Optional;

/**
 * Supplies a backup vault's access policy to IAM policy evaluation, for a call on the vault or on a recovery point it
 * holds, together with the account that owns the resource: the one in its ARN, also when the resource does not exist
 * or has no policy, so a call on another account's resource is judged as cross-account.
 *
 * <p>AWS Backup refuses every cross-account request but {@code backup:CopyIntoBackupVault} "regardless of the AWS
 * Backup vault's access policy" (Developer Guide, Vault access policies), so for any other action a caller of another
 * account is given no policy to be allowed by, and is refused for lacking the owner's allow.
 */
@ApplicationScoped
public class BackupResourcePolicyProvider implements ResourcePolicyProvider {

    private static final String NAMESPACE = "backup";
    private static final String CROSS_ACCOUNT_ACTION = "backup:CopyIntoBackupVault";

    private final BackupService backup;
    private final RegionResolver regionResolver;

    @Inject
    public BackupResourcePolicyProvider(BackupService backup, RegionResolver regionResolver) {
        this.backup = backup;
        this.regionResolver = regionResolver;
    }

    @Override
    public List<ResourcePolicy> getResourcePolicies(String credentialScope, String resourceArn) {
        return getResourcePolicies(credentialScope, null, resourceArn);
    }

    @Override
    public List<ResourcePolicy> getResourcePolicies(String credentialScope, String action, String resourceArn) {
        if (!NAMESPACE.equals(credentialScope)) {
            return List.of();
        }
        Optional<AwsArnUtils.Arn> parsed = ResourcePolicyProvider.regionalArn(resourceArn, NAMESPACE);
        if (parsed.isEmpty() || parsed.get().resource().contains("*")) {
            return List.of();
        }
        String owner = parsed.get().accountId();
        boolean applies = owner.equals(regionResolver.getAccountId()) || CROSS_ACCOUNT_ACTION.equalsIgnoreCase(action);
        String policy = applies ? backup.findVaultAccessPolicy(resourceArn).orElse(null) : null;
        return List.of(new ResourcePolicy(policy, owner));
    }
}
