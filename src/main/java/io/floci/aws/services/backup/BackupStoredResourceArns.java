package io.floci.aws.services.backup;

import io.floci.aws.core.common.AwsArnUtils;
import io.floci.aws.core.common.StoredResourceArns;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/** IAM's lookup of the tags AWS Backup holds on a backup vault or a backup plan, for the {@code backup} namespace. */
@ApplicationScoped
public class BackupStoredResourceArns implements StoredResourceArns {

    private static final String NAMESPACE = "backup";

    private final BackupService backup;

    @Inject
    public BackupStoredResourceArns(BackupService backup) {
        this.backup = backup;
    }

    @Override
    public String namespace() {
        return NAMESPACE;
    }

    /** A request names a vault or a plan by the name or id in its path, which its ARN holds: nothing to find. */
    @Override
    public Optional<String> find(String type, List<String> names, String region) {
        return Optional.empty();
    }

    /**
     * The tags of the vault or the plan whose ARN is {@code arn}, matched on the whole ARN its record holds, so an
     * ARN of another account or Region names none. A tag without a value reads as an empty one.
     */
    @Override
    public Map<String, String> storedTags(String arn) {
        if (!AwsArnUtils.isArnFor(arn, NAMESPACE)) {
            return Map.of();
        }
        return StoredResourceArns.withEmptyValues(backup.storedTags(arn));
    }
}
