#!/usr/bin/env python3
"""Regenerate src/main/resources/aws/sns-cloudtrail-shapes.json from botocore's SNS model.

CloudTrail records SNS's control plane calls, and `SnsCloudTrailEvents` writes each record's
`requestParameters` and `responseElements` from the call's request and result. The file is
`request_shapes.build`'s, as IAM's (`regen_iam_cloudtrail_shapes.py`): each operation's input shape,
its result shape, every shape they reach with its type and the `sensitive` flag, and every error SNS
models, from the code it answers with to its shape's name.

SNS's management events are the calls its guide lists, `Publish` and `PublishBatch` being data
events, so only those operations' shapes are vendored (`OPERATIONS`). Beside the shape a member
names, SNS's model gives its members no trait; any other stops the generation.

The model is botocore's `sns/2010-03-31/` (Apache-2.0, https://github.com/boto/botocore), located, in
order, at `--botocore-data`, the `local/aws/botocore` checkout, then the installed `botocore`
package, which `requirements.txt` pins so CI regenerates the same bytes.

Run from anywhere in the repo:
    python3 tools/aws/regen_sns_cloudtrail_shapes.py            # rewrite the vendored file in place
    python3 tools/aws/regen_sns_cloudtrail_shapes.py --check    # exit 1 when the vendored file is stale
"""
from __future__ import annotations

import sys
from pathlib import Path

import request_shapes
from request_shapes import REPO_ROOT

OUTPUT = REPO_ROOT / "src/main/resources/aws/sns-cloudtrail-shapes.json"
MODEL = Path("sns/2010-03-31")

# The calls the SNS guide lists as management events, whose shapes are vendored.
OPERATIONS = (
    "AddPermission", "CheckIfPhoneNumberIsOptedOut", "ConfirmSubscription", "CreatePlatformApplication",
    "CreatePlatformEndpoint", "CreateSMSSandboxPhoneNumber", "CreateTopic", "DeleteEndpoint",
    "DeletePlatformApplication", "DeleteSMSSandboxPhoneNumber", "DeleteTopic", "GetDataProtectionPolicy",
    "GetEndpointAttributes", "GetPlatformApplicationAttributes", "GetSMSAttributes",
    "GetSMSSandboxAccountStatus", "GetSubscriptionAttributes", "GetTopicAttributes",
    "ListEndpointsByPlatformApplication", "ListOriginationNumbers", "ListPhoneNumbersOptedOut",
    "ListPlatformApplications", "ListSMSSandboxPhoneNumbers", "ListSubscriptions", "ListSubscriptionsByTopic",
    "ListTagsForResource", "ListTopics", "OptInPhoneNumber", "PutDataProtectionPolicy", "RemovePermission",
    "SetEndpointAttributes", "SetPlatformApplicationAttributes", "SetSMSAttributes", "SetSubscriptionAttributes",
    "SetTopicAttributes", "Subscribe", "TagResource", "Unsubscribe", "UntagResource",
    "VerifySMSSandboxPhoneNumber",
)

MEMBER_TRAITS = {"shape", "documentation"}
readable = request_shapes.record_check(MEMBER_TRAITS)


def main(argv: list[str] | None = None) -> int:
    return request_shapes.main(argv, script=__file__, model=MODEL, output=OUTPUT, description=__doc__,
                               results=True, sensitive=True, errors=True, check=readable, subset=OPERATIONS)


if __name__ == "__main__":
    sys.exit(main())
