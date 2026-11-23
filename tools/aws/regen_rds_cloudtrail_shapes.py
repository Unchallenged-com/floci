#!/usr/bin/env python3
"""Regenerate src/main/resources/aws/rds-cloudtrail-shapes.json from botocore's RDS model.

CloudTrail records RDS's API calls, and `RdsCloudTrailEvents` writes each record's
`requestParameters` and `responseElements` from the call's request and result. The file is
`request_shapes.build`'s, as IAM's (`regen_iam_cloudtrail_shapes.py`): each operation's input shape,
its result shape, every shape they reach with its type and the `sensitive` flag, and every error
RDS models, from the code it answers with to its shape's name: a record names a failed call's error
after its shape (`DBInstanceNotFound` as `DBInstanceNotFoundFault`). Every code RDS models is answered
by one shape alone; a model where two shapes answer one code stops the generation, since the record
would then need the shape the operation itself declares.

"All Amazon RDS actions are logged by CloudTrail"
(https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/logging-using-cloudtrail.html), so every
operation of the model is vendored. A list the model names the members of (`locationName`) carries
that name as `memberName`: a Query request numbers its members under it
(`ValuesToAdd.AttributeValue.1`, `VpcSecurityGroupIds.VpcSecurityGroupId.1`).

The model is botocore's `rds/2014-10-31/` (Apache-2.0, https://github.com/boto/botocore), located, in
order, at `--botocore-data`, the `local/aws/botocore` checkout, then the installed `botocore`
package, which `requirements.txt` pins so CI regenerates the same bytes.

Run from anywhere in the repo:
    python3 tools/aws/regen_rds_cloudtrail_shapes.py            # rewrite the vendored file in place
    python3 tools/aws/regen_rds_cloudtrail_shapes.py --check    # exit 1 when the vendored file is stale
"""
from __future__ import annotations

import sys
from pathlib import Path

import request_shapes
from request_shapes import REPO_ROOT

OUTPUT = REPO_ROOT / "src/main/resources/aws/rds-cloudtrail-shapes.json"
MODEL = Path("rds/2014-10-31")

# The member traits `CloudTrailShapes` reads beside the shape a member names. Any other, or a shape
# type the record does not read, is one it would pass over or misread, so the generation stops
# rather than vendoring it.
MEMBER_TRAITS = {"shape", "documentation"}
readable = request_shapes.record_check(MEMBER_TRAITS)


def main(argv: list[str] | None = None) -> int:
    return request_shapes.main(argv, script=__file__, model=MODEL, output=OUTPUT, description=__doc__,
                               results=True, sensitive=True, errors=True, check=readable,
                               list_member_names=True)


if __name__ == "__main__":
    sys.exit(main())
