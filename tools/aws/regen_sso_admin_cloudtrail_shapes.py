#!/usr/bin/env python3
"""Regenerate src/main/resources/aws/sso-admin-cloudtrail-shapes.json from botocore's SSO Admin model.

CloudTrail records the public IAM Identity Center operations under the event source sso.amazonaws.com
(https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-info-in-cloudtrail.html), and
`SsoAdminCloudTrailEvents` writes each record's `requestParameters` and `responseElements` from the call's
JSON request and result. The file is `request_shapes.build`'s, as SQS's (`regen_sqs_cloudtrail_shapes.py`):
each operation's input shape, its result shape, every shape they reach with its type, the `sensitive` flag
and the `document` flag (an authentication method's `ActorPolicy`, any JSON, which a record writes as
sent), and every error SSO Admin models, from the code it answers with to its shape's name.

Only the operations the guide lists are recorded, so only those are vendored (`OPERATIONS`, the guide's list,
which `regen_cloudtrail_events.py` carries too).

SSO Admin's model is a JSON one, so one member trait beside the shape a member names says nothing of how a
record names or types it: `idempotencyToken`, which only lets an SDK fill the member in. Any other stops the
generation.

The model is botocore's `sso-admin/2020-07-20/` (Apache-2.0, https://github.com/boto/botocore), located, in
order, at `--botocore-data`, the `local/aws/botocore` checkout, then the installed `botocore` package, which
`requirements.txt` pins so CI regenerates the same bytes.

Run from anywhere in the repo:
    python3 tools/aws/regen_sso_admin_cloudtrail_shapes.py            # rewrite the vendored file in place
    python3 tools/aws/regen_sso_admin_cloudtrail_shapes.py --check    # exit 1 when the vendored file is stale
"""
from __future__ import annotations

import sys
from pathlib import Path

import request_shapes
from regen_cloudtrail_events import SERVICES
from request_shapes import REPO_ROOT

OUTPUT = REPO_ROOT / "src/main/resources/aws/sso-admin-cloudtrail-shapes.json"
MODEL = Path("sso-admin/2020-07-20")

OPERATIONS = SERVICES["sso"].management_events

MEMBER_TRAITS = {"shape", "documentation", "idempotencyToken"}
readable = request_shapes.record_check(MEMBER_TRAITS)


def main(argv: list[str] | None = None) -> int:
    return request_shapes.main(argv, script=__file__, model=MODEL, output=OUTPUT, description=__doc__,
                               results=True, sensitive=True, errors=True, check=readable,
                               subset=OPERATIONS, documents=True)


if __name__ == "__main__":
    sys.exit(main())
