#!/usr/bin/env python3
"""Regenerate src/main/resources/aws/account-cloudtrail-shapes.json from botocore's Account model.

CloudTrail records every Account Management call, and `AccountCloudTrailEvents` writes each record's
`requestParameters` from the call's request. The file is `request_shapes.build`'s, as Lambda's
(`regen_lambda_cloudtrail_shapes.py`): each operation's input shape, its result shape, every shape they
reach with its type and the `sensitive` flag (`Name`, `EmailAddress`, `PhoneNumber`, a contact's address),
and every error Account models, from the code it answers with to its shape's name.

"AWS CloudTrail logs all Account Management API operations"
(https://docs.aws.amazon.com/accounts/latest/reference/monitoring-cloudtrail.html), but only the calls Floci
serves are recorded, so only those operations' shapes are vendored (`OPERATIONS`).

Account's model is a REST-JSON one whose calls carry every member in their body, so their members carry no
trait beside the shape they name. Any other stops the generation.

The model is botocore's `account/2021-02-01/` (Apache-2.0, https://github.com/boto/botocore), located, in
order, at `--botocore-data`, the `local/aws/botocore` checkout, then the installed `botocore` package, which
`requirements.txt` pins so CI regenerates the same bytes.

Run from anywhere in the repo:
    python3 tools/aws/regen_account_cloudtrail_shapes.py            # rewrite the vendored file in place
    python3 tools/aws/regen_account_cloudtrail_shapes.py --check    # exit 1 when the vendored file is stale
"""
from __future__ import annotations

import sys
from pathlib import Path

import request_shapes
from request_shapes import REPO_ROOT

OUTPUT = REPO_ROOT / "src/main/resources/aws/account-cloudtrail-shapes.json"
MODEL = Path("account/2021-02-01")

# The Account Management calls Floci serves, whose shapes are vendored.
OPERATIONS = (
    "DeleteAlternateContact", "GetAccountInformation", "GetAlternateContact", "GetContactInformation",
    "PutAccountName", "PutAlternateContact", "PutContactInformation",
)

MEMBER_TRAITS = {"shape", "documentation"}
readable = request_shapes.record_check(MEMBER_TRAITS)


def main(argv: list[str] | None = None) -> int:
    return request_shapes.main(argv, script=__file__, model=MODEL, output=OUTPUT, description=__doc__,
                               results=True, sensitive=True, errors=True, check=readable,
                               subset=OPERATIONS)


if __name__ == "__main__":
    sys.exit(main())
