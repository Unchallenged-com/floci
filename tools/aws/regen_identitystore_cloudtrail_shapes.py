#!/usr/bin/env python3
"""Regenerate src/main/resources/aws/identitystore-cloudtrail-shapes.json from botocore's Identity Store model.

CloudTrail records the public Identity Store operations under the event source identitystore.amazonaws.com
(https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-info-in-cloudtrail.html), and
`IdentityStoreCloudTrailEvents` writes each record's `requestParameters` and `responseElements` from the
call's JSON request and result. The file is `request_shapes.build`'s, as SQS's
(`regen_sqs_cloudtrail_shapes.py`): each operation's input shape, its result shape, every shape they reach with
its type and the `sensitive` flag (`UserName`, `GroupDisplayName`, the user attributes'
`SensitiveStringType`, the external IDs), and every error the Identity Store models, from the code it answers
with to its shape's name.

`AttributeValue` is marked sensitive as well. It is the value of the attribute an `AttributeOperation`,
a `UniqueAttribute` or an extension names (`displayName`, `userName`, `emails`, ...), which the model types as
a document rather than as the attribute's own, sensitive, shape; IAM Identity Center writes a group's
displayName as HIDDEN_DUE_TO_SECURITY_REASONS in CreateGroup's and UpdateGroup's events (AWS Security Blog,
Important changes to CloudTrail events for AWS IAM Identity Center, 2024-11-19, updated 2025-11-26).

Only the operations the guide lists are recorded, so only those are vendored (`OPERATIONS`, the guide's list,
which `regen_cloudtrail_events.py` carries too).

The Identity Store's model is a JSON one, so two member traits beside the shape a member names say nothing
of how a record names or types it: `box`, which only makes a number nullable in some SDKs, and a deprecation,
which leaves the member as it is. Any other stops the generation.

The model is botocore's `identitystore/2020-06-15/` (Apache-2.0, https://github.com/boto/botocore), located,
in order, at `--botocore-data`, the `local/aws/botocore` checkout, then the installed `botocore` package,
which `requirements.txt` pins so CI regenerates the same bytes.

Run from anywhere in the repo:
    python3 tools/aws/regen_identitystore_cloudtrail_shapes.py            # rewrite the vendored file in place
    python3 tools/aws/regen_identitystore_cloudtrail_shapes.py --check    # exit 1 when the vendored file is stale
"""
from __future__ import annotations

import sys
from pathlib import Path

import request_shapes
from regen_cloudtrail_events import SERVICES
from request_shapes import REPO_ROOT

OUTPUT = REPO_ROOT / "src/main/resources/aws/identitystore-cloudtrail-shapes.json"
MODEL = Path("identitystore/2020-06-15")

OPERATIONS = SERVICES["identitystore"].management_events

# The document that carries an attribute's value, whatever the attribute.
ATTRIBUTE_VALUE = "AttributeValue"

MEMBER_TRAITS = {"shape", "documentation", "box", "deprecated", "deprecatedMessage"}
readable = request_shapes.record_check(MEMBER_TRAITS)


def hide_attribute_values(model: dict) -> dict:
    """The model, with the document that carries an attribute's value marked sensitive."""
    model["shapes"][ATTRIBUTE_VALUE]["sensitive"] = True
    return model


def main(argv: list[str] | None = None) -> int:
    return request_shapes.main(argv, script=__file__, model=MODEL, output=OUTPUT, description=__doc__,
                               prepare=hide_attribute_values, results=True, sensitive=True, errors=True,
                               check=readable, subset=OPERATIONS)


if __name__ == "__main__":
    sys.exit(main())
