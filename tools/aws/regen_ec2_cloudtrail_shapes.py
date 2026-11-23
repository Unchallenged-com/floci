#!/usr/bin/env python3
"""Regenerate src/main/resources/aws/ec2-cloudtrail-shapes.json from botocore's EC2 model.

CloudTrail records EC2's API calls, and `Ec2CloudTrailEvents` writes each record's
`requestParameters` and `responseElements` from the call's request and result. The file is
`request_shapes.build`'s, as IAM's (`regen_iam_cloudtrail_shapes.py`): each operation's input shape,
its result shape, every shape they reach with its type and the `sensitive` flag, and every error
EC2 models, from the code it answers with to its shape's name.

EC2's model is too large to vendor whole, and Floci records only the EC2 calls a record shows,
so only those operations' shapes are vendored (`OPERATIONS`).

An EC2 record names a result's members as its XML does (`instancesSet`, `item`), which the model
gives as each member's `locationName`, so the file keys members by that name and keeps only results:
the requests follow EC2's own schema rather than botocore's (`Ec2CloudTrailEvents`). Beside the shape a
member names, `locationName` and `queryName` (the names on the wire), a deprecation, `box` and
`idempotencyToken` say nothing of how a record types or redacts a member. Any other stops the
generation.

The model is botocore's `ec2/2016-11-15/` (Apache-2.0, https://github.com/boto/botocore), located, in
order, at `--botocore-data`, the `local/aws/botocore` checkout, then the installed `botocore`
package, which `requirements.txt` pins so CI regenerates the same bytes.

Run from anywhere in the repo:
    python3 tools/aws/regen_ec2_cloudtrail_shapes.py            # rewrite the vendored file in place
    python3 tools/aws/regen_ec2_cloudtrail_shapes.py --check    # exit 1 when the vendored file is stale
"""
from __future__ import annotations

import sys
from pathlib import Path

import request_shapes
from request_shapes import REPO_ROOT

OUTPUT = REPO_ROOT / "src/main/resources/aws/ec2-cloudtrail-shapes.json"
MODEL = Path("ec2/2016-11-15")

# The EC2 calls Ec2CloudTrailEvents records, whose shapes are vendored.
OPERATIONS = (
    "AttachVolume", "AuthorizeSecurityGroupEgress", "AuthorizeSecurityGroupIngress", "CopyImage",
    "CopySnapshot", "CreateFlowLogs", "CreateImage", "CreateKeyPair", "CreateNetworkAcl",
    "CreateNetworkAclEntry", "CreateSecurityGroup", "CreateSnapshot", "CreateVolume", "DeleteFlowLogs",
    "DeleteNetworkAcl", "DeleteNetworkAclEntry", "DeleteSecurityGroup", "DeleteSnapshot", "DeleteVolume",
    "DeregisterImage", "DetachVolume", "GetPasswordData", "ImportKeyPair", "ModifyImageAttribute",
    "ModifyInstanceAttribute", "ModifySecurityGroupRules", "ModifySnapshotAttribute",
    "ReplaceNetworkAclEntry", "RevokeSecurityGroupEgress", "RevokeSecurityGroupIngress", "RunInstances",
    "StartInstances", "StopInstances", "TerminateInstances",
)

MEMBER_TRAITS = {"shape", "documentation", "locationName", "queryName", "deprecated", "deprecatedMessage", "box", "idempotencyToken"}
readable = request_shapes.record_check(MEMBER_TRAITS)


def main(argv: list[str] | None = None) -> int:
    return request_shapes.main(argv, script=__file__, model=MODEL, output=OUTPUT, description=__doc__,
                               results=True, sensitive=True, errors=True, check=readable,
                               subset=OPERATIONS, xml_names=True)


if __name__ == "__main__":
    sys.exit(main())
