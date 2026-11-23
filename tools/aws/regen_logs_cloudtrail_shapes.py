#!/usr/bin/env python3
"""Regenerate src/main/resources/aws/logs-cloudtrail-shapes.json from botocore's CloudWatch Logs model.

CloudTrail records CloudWatch Logs's API calls, and `LogsCloudTrailEvents` writes each record's
`requestParameters` and `responseElements` from the call's request and result. The file is
`request_shapes.build`'s, as IAM's (`regen_iam_cloudtrail_shapes.py`): each operation's input shape,
its result shape, every shape they reach with its type and the `sensitive` flag, and every error
CloudWatch Logs models, from the code it answers with to its shape's name.

CloudWatch Logs' model is a JSON one. Beside the shape a member names, these member traits say nothing
of how a record names, types or redacts it: a deprecation, which leaves the member as it is, `box`,
which only says the member has no default value, and `idempotencyToken`, which only says an SDK fills
the member in when the caller does not. Any other stops the generation.

The model is botocore's `logs/2014-03-28/` (Apache-2.0, https://github.com/boto/botocore), located, in
order, at `--botocore-data`, the `local/aws/botocore` checkout, then the installed `botocore`
package, which `requirements.txt` pins so CI regenerates the same bytes.

Run from anywhere in the repo:
    python3 tools/aws/regen_logs_cloudtrail_shapes.py            # rewrite the vendored file in place
    python3 tools/aws/regen_logs_cloudtrail_shapes.py --check    # exit 1 when the vendored file is stale
"""
from __future__ import annotations

import sys
from pathlib import Path

import request_shapes
from request_shapes import REPO_ROOT

OUTPUT = REPO_ROOT / "src/main/resources/aws/logs-cloudtrail-shapes.json"
MODEL = Path("logs/2014-03-28")

MEMBER_TRAITS = {"shape", "documentation", "deprecated", "deprecatedMessage", "box", "idempotencyToken"}
readable = request_shapes.record_check(MEMBER_TRAITS)


def main(argv: list[str] | None = None) -> int:
    return request_shapes.main(argv, script=__file__, model=MODEL, output=OUTPUT, description=__doc__,
                               results=True, sensitive=True, errors=True, check=readable)


if __name__ == "__main__":
    sys.exit(main())
