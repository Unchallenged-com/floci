#!/usr/bin/env python3
"""Regenerate src/main/resources/aws/organizations-cloudtrail-shapes.json from botocore's Organizations model.

CloudTrail records every Organizations call, and `OrganizationsCloudTrailEvents` writes each record's
`requestParameters` and `responseElements` from the call's JSON request and result. The file is
`request_shapes.build`'s, as SQS's (`regen_sqs_cloudtrail_shapes.py`): each operation's input shape, its
result shape, every shape they reach with its type and the `sensitive` flag (`Email`, `AccountName`,
`HandshakeNotes`), and every error Organizations models, from the code it answers with to its shape's name.

"All AWS Organizations actions are logged by CloudTrail"
(https://docs.aws.amazon.com/organizations/latest/userguide/orgs_cloudtrail-integration.html), but only the
calls Floci serves are recorded, so only those operations' shapes are vendored (`OPERATIONS`).

Organizations' model is a JSON one whose members carry no trait beside the shape they name. Any other stops
the generation.

The model is botocore's `organizations/2016-11-28/` (Apache-2.0, https://github.com/boto/botocore), located,
in order, at `--botocore-data`, the `local/aws/botocore` checkout, then the installed `botocore` package,
which `requirements.txt` pins so CI regenerates the same bytes.

Run from anywhere in the repo:
    python3 tools/aws/regen_organizations_cloudtrail_shapes.py            # rewrite the vendored file in place
    python3 tools/aws/regen_organizations_cloudtrail_shapes.py --check    # exit 1 when the vendored file is stale
"""
from __future__ import annotations

import sys
from pathlib import Path

import request_shapes
from request_shapes import REPO_ROOT

OUTPUT = REPO_ROOT / "src/main/resources/aws/organizations-cloudtrail-shapes.json"
MODEL = Path("organizations/2016-11-28")

# The Organizations calls Floci serves, whose shapes are vendored.
OPERATIONS = (
    "AcceptHandshake", "AttachPolicy", "CancelHandshake", "CloseAccount", "CreateAccount",
    "CreateGovCloudAccount", "CreateOrganization", "CreateOrganizationalUnit", "CreatePolicy",
    "DeclineHandshake", "DeleteOrganization", "DeleteOrganizationalUnit", "DeletePolicy",
    "DeleteResourcePolicy", "DeregisterDelegatedAdministrator", "DescribeAccount",
    "DescribeCreateAccountStatus", "DescribeEffectivePolicy", "DescribeHandshake", "DescribeOrganization",
    "DescribeOrganizationalUnit", "DescribePolicy", "DescribeResourcePolicy", "DetachPolicy",
    "DisableAWSServiceAccess", "DisablePolicyType", "EnableAWSServiceAccess", "EnableAllFeatures",
    "EnablePolicyType", "InviteAccountToOrganization", "LeaveOrganization",
    "ListAWSServiceAccessForOrganization", "ListAccounts", "ListAccountsForParent",
    "ListAccountsWithInvalidEffectivePolicy", "ListChildren", "ListCreateAccountStatus",
    "ListDelegatedAdministrators", "ListDelegatedServicesForAccount", "ListHandshakesForAccount",
    "ListHandshakesForOrganization", "ListOrganizationalUnitsForParent", "ListParents", "ListPolicies",
    "ListPoliciesForTarget", "ListRoots", "ListTagsForResource", "ListTargetsForPolicy", "MoveAccount",
    "PutResourcePolicy", "RegisterDelegatedAdministrator", "RemoveAccountFromOrganization", "TagResource",
    "UntagResource", "UpdateOrganizationalUnit", "UpdatePolicy",
)

MEMBER_TRAITS = {"shape", "documentation"}
readable = request_shapes.record_check(MEMBER_TRAITS)


def main(argv: list[str] | None = None) -> int:
    return request_shapes.main(argv, script=__file__, model=MODEL, output=OUTPUT, description=__doc__,
                               results=True, sensitive=True, errors=True, check=readable,
                               subset=OPERATIONS)


if __name__ == "__main__":
    sys.exit(main())
