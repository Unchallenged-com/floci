#!/usr/bin/env python3
"""Regenerate src/main/resources/aws/ec2-instance-connect-cloudtrail-shapes.json from botocore's
EC2 Instance Connect model.

CloudTrail records EC2 Instance Connect's API calls, and `InstanceConnectCloudTrailEvents` writes each
record's `requestParameters` and `responseElements` from the call's request and result. The file is
`request_shapes.build`'s, as IAM's (`regen_iam_cloudtrail_shapes.py`): each operation's input shape,
its result shape, every shape they reach with its type and the `sensitive` flag, and every error
EC2 Instance Connect models, from the code it answers with to its shape's name.

EC2 Instance Connect's model is a JSON one. Beside the shape a member names, no member trait it
carries says anything of how a record names, types or redacts a member. Any other stops the
generation.

The model is botocore's `ec2-instance-connect/2018-04-02/` (Apache-2.0, https://github.com/boto/botocore),
located, in order, at `--botocore-data`, the `local/aws/botocore` checkout, then the installed `botocore`
package, which `requirements.txt` pins so CI regenerates the same bytes.

Run from anywhere in the repo:
    python3 tools/aws/regen_ec2_instance_connect_cloudtrail_shapes.py            # rewrite the vendored file
    python3 tools/aws/regen_ec2_instance_connect_cloudtrail_shapes.py --check    # exit 1 when it is stale
"""
from __future__ import annotations

import sys
from pathlib import Path

import request_shapes
from request_shapes import REPO_ROOT

OUTPUT = REPO_ROOT / "src/main/resources/aws/ec2-instance-connect-cloudtrail-shapes.json"
MODEL = Path("ec2-instance-connect/2018-04-02")

MEMBER_TRAITS = {"shape", "documentation"}
readable = request_shapes.record_check(MEMBER_TRAITS)


def main(argv: list[str] | None = None) -> int:
    return request_shapes.main(argv, script=__file__, model=MODEL, output=OUTPUT, description=__doc__,
                               results=True, sensitive=True, errors=True, check=readable)


if __name__ == "__main__":
    sys.exit(main())
