#!/usr/bin/env python3
"""Regenerate src/main/resources/aws/sts-cloudtrail-shapes.json from botocore's STS model.

CloudTrail records every STS API call, and `StsCloudTrailEvents` writes each record's
`requestParameters` and `responseElements` from the call's request and result, read through
`CloudTrailShapes` as IAM's are. The walk is `request_shapes.build`'s, as for every other vendored
shape file:

- `operations`: each operation's input shape, and `results` each one's output shape and the element
  its result is wrapped in on the wire (`resultWrapper`, `AssumeRoleResult`).
- `shapes`: every shape reachable from them, with its type and the shapes its members, list
  elements and map values have. A number, such as `sessionTokenSize`, is typed as one in the record
  because its shape says so. A shape the model marks `sensitive` (a secret access key, a SAML
  assertion, a web identity token) carries `"sensitive": true`, and the record leaves it out.

No error table is kept: an STS error is recorded under the code STS answers it with.

The model is botocore's `sts/2011-06-15/` (Apache-2.0, https://github.com/boto/botocore), located,
in order, at `--botocore-data`, the `local/aws/botocore` checkout, then the installed `botocore`
package, which `requirements.txt` pins so CI regenerates the same bytes.

Run from anywhere in the repo:
    python3 tools/aws/regen_sts_cloudtrail_shapes.py            # rewrite the vendored file in place
    python3 tools/aws/regen_sts_cloudtrail_shapes.py --check    # exit 1 when the vendored file is stale
"""
from __future__ import annotations

import sys
from pathlib import Path

import request_shapes
from request_shapes import REPO_ROOT

OUTPUT = REPO_ROOT / "src/main/resources/aws/sts-cloudtrail-shapes.json"
MODEL = Path("sts/2011-06-15")

# The member traits `CloudTrailShapes` reads beside the shape a member names, as for IAM's, and the
# deprecation traits, which leave the member as it is: the record still carries the deprecated
# `packedPolicySize` beside the two members that replace it (the IAM User Guide's AssumeRoleWithSAML
# example, https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html).
MEMBER_TRAITS = {"shape", "documentation", "deprecated", "deprecatedMessage", "deprecatedSince"}
readable = request_shapes.record_check(MEMBER_TRAITS)


def main(argv: list[str] | None = None) -> int:
    return request_shapes.main(argv, script=__file__, model=MODEL, output=OUTPUT, description=__doc__,
                               results=True, sensitive=True, check=readable)


if __name__ == "__main__":
    sys.exit(main())
