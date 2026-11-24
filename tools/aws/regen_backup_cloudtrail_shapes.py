#!/usr/bin/env python3
"""Regenerate src/main/resources/aws/backup-cloudtrail-shapes.json from botocore's AWS Backup model.

CloudTrail records AWS Backup's API calls, and `BackupCloudTrailEvents` writes each record's
`requestParameters` and `responseElements` from the call's request and result. The file is
`request_shapes.build`'s, as Lambda's (`regen_lambda_cloudtrail_shapes.py`): each operation's input
shape, its result shape, every shape they reach with its type and the `sensitive` flag, and every
error AWS Backup models, from the code it answers with to its shape's name.

Only the calls Floci serves are vendored (`OPERATIONS`), the management events
`regen_cloudtrail_events.py` lists for the service.

AWS Backup's model is a REST-JSON one: a request carries some of its members in its path and its
query rather than its body, and a record writes them as members all the same (`"backupVaultName"`,
`"recoveryPointArn"`, as the guide's DeleteRecoveryPoint example does), so those members are kept
with the structure's `locations`. Beside the shape a member names, `location` and `locationName`
(where it travels), a deprecation, `box` and `idempotencyToken` say nothing of how a record types or
redacts a member. Any other stops the generation.

The model is botocore's `backup/2018-11-15/` (Apache-2.0, https://github.com/boto/botocore), located,
in order, at `--botocore-data`, the `local/aws/botocore` checkout, then the installed `botocore`
package, which `requirements.txt` pins so CI regenerates the same bytes.

Run from anywhere in the repo:
    python3 tools/aws/regen_backup_cloudtrail_shapes.py            # rewrite the vendored file in place
    python3 tools/aws/regen_backup_cloudtrail_shapes.py --check    # exit 1 when the vendored file is stale
"""
from __future__ import annotations

import sys
from pathlib import Path

import request_shapes
from request_shapes import REPO_ROOT

OUTPUT = REPO_ROOT / "src/main/resources/aws/backup-cloudtrail-shapes.json"
MODEL = Path("backup/2018-11-15")

# The AWS Backup calls Floci serves, whose shapes are vendored.
OPERATIONS = (
    "CreateBackupPlan", "CreateBackupSelection", "CreateBackupVault", "CreateLogicallyAirGappedBackupVault",
    "DeleteBackupPlan", "DeleteBackupSelection", "DeleteBackupVault", "DeleteBackupVaultAccessPolicy",
    "DeleteBackupVaultLockConfiguration", "DeleteBackupVaultNotifications", "DeleteRecoveryPoint",
    "DescribeBackupJob", "DescribeBackupVault", "DescribeRecoveryPoint", "GetBackupPlan",
    "GetBackupSelection", "GetBackupVaultAccessPolicy", "GetBackupVaultNotifications",
    "GetSupportedResourceTypes", "ListBackupJobs", "ListBackupPlans", "ListBackupSelections",
    "ListBackupVaults", "ListRecoveryPointsByBackupVault", "ListTags", "PutBackupVaultAccessPolicy",
    "PutBackupVaultLockConfiguration", "PutBackupVaultNotifications", "StartBackupJob", "StopBackupJob",
    "TagResource", "UntagResource", "UpdateBackupPlan",
)

MEMBER_TRAITS = {"shape", "documentation", "location", "locationName", "deprecated", "deprecatedMessage", "box", "idempotencyToken"}
readable = request_shapes.record_check(MEMBER_TRAITS)


def main(argv: list[str] | None = None) -> int:
    return request_shapes.main(argv, script=__file__, model=MODEL, output=OUTPUT, description=__doc__,
                               results=True, sensitive=True, errors=True, check=readable,
                               subset=OPERATIONS, located=True)


if __name__ == "__main__":
    sys.exit(main())
