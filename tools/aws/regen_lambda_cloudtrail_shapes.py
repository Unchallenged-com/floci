#!/usr/bin/env python3
"""Regenerate src/main/resources/aws/lambda-cloudtrail-shapes.json from botocore's Lambda model.

CloudTrail records Lambda's API calls, and `LambdaCloudTrailEvents` writes each record's
`requestParameters` and `responseElements` from the call's request and result. The file is
`request_shapes.build`'s, as IAM's (`regen_iam_cloudtrail_shapes.py`): each operation's input shape,
its result shape, every shape they reach with its type and the `sensitive` flag, and every error
Lambda models, from the code it answers with to its shape's name.

Lambda's management events are the calls its guide lists, and its other calls (Invoke, a data event)
reach shapes the record does not read, such as an event stream, so only those operations' shapes are
vendored (`OPERATIONS`).

Lambda's model is a REST-JSON one: a request carries some of its members in its path and its query
rather than its body, and the record writes them as members all the same (`"functionName"`,
`"maxItems"`), so those members are kept with the structure's `locations`. Beside the shape a member
names, `location` and `locationName` (where it travels), a deprecation, `box` and `idempotencyToken`
say nothing of how a record types or redacts a member. Any other stops the generation.

The model is botocore's `lambda/2015-03-31/` (Apache-2.0, https://github.com/boto/botocore), located, in
order, at `--botocore-data`, the `local/aws/botocore` checkout, then the installed `botocore`
package, which `requirements.txt` pins so CI regenerates the same bytes.

Run from anywhere in the repo:
    python3 tools/aws/regen_lambda_cloudtrail_shapes.py            # rewrite the vendored file in place
    python3 tools/aws/regen_lambda_cloudtrail_shapes.py --check    # exit 1 when the vendored file is stale
"""
from __future__ import annotations

import sys
from pathlib import Path

import request_shapes
from request_shapes import REPO_ROOT

OUTPUT = REPO_ROOT / "src/main/resources/aws/lambda-cloudtrail-shapes.json"
MODEL = Path("lambda/2015-03-31")

# The calls the Lambda guide lists as management events, whose shapes are vendored.
OPERATIONS = (
    "AddLayerVersionPermission", "AddPermission", "CreateAlias", "CreateEventSourceMapping",
    "CreateFunction", "CreateFunctionUrlConfig", "DeleteAlias", "DeleteCodeSigningConfig",
    "DeleteEventSourceMapping", "DeleteFunction", "DeleteFunctionConcurrency", "DeleteFunctionUrlConfig",
    "DeleteProvisionedConcurrencyConfig", "GetAccountSettings", "GetAlias", "GetEventSourceMapping",
    "GetFunction", "GetFunctionCodeSigningConfig", "GetFunctionConfiguration",
    "GetFunctionEventInvokeConfig", "GetFunctionUrlConfig", "GetPolicy", "ListAliases",
    "ListEventSourceMappings", "ListFunctionUrlConfigs", "ListFunctions", "ListLayers", "ListTags",
    "ListVersionsByFunction", "PublishLayerVersion", "PublishVersion", "PutFunctionCodeSigningConfig",
    "PutFunctionConcurrency", "PutFunctionEventInvokeConfig", "PutProvisionedConcurrencyConfig",
    "PutRuntimeManagementConfig", "RemovePermission", "TagResource", "UntagResource", "UpdateAlias",
    "UpdateCodeSigningConfig", "UpdateEventSourceMapping", "UpdateFunctionCode",
    "UpdateFunctionConfiguration", "UpdateFunctionEventInvokeConfig", "UpdateFunctionUrlConfig",
)

MEMBER_TRAITS = {"shape", "documentation", "location", "locationName", "deprecated", "deprecatedMessage", "box", "idempotencyToken"}
readable = request_shapes.record_check(MEMBER_TRAITS)


def main(argv: list[str] | None = None) -> int:
    return request_shapes.main(argv, script=__file__, model=MODEL, output=OUTPUT, description=__doc__,
                               results=True, sensitive=True, errors=True, check=readable,
                               subset=OPERATIONS, located=True)


if __name__ == "__main__":
    sys.exit(main())
