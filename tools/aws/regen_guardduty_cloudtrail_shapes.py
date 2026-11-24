#!/usr/bin/env python3
"""Regenerate src/main/resources/aws/guardduty-cloudtrail-shapes.json from botocore's GuardDuty model.

CloudTrail records GuardDuty's API calls, and `GuardDutyCloudTrailEvents` writes each record's
`requestParameters` and `responseElements` from the call's request and result. The file is
`request_shapes.build`'s, as Lambda's (`regen_lambda_cloudtrail_shapes.py`): each operation's input shape,
its result shape, every shape they reach with its type and the `sensitive` flag.

"CloudTrail logs all the GuardDuty API operations"
(https://docs.aws.amazon.com/guardduty/latest/ug/logging-using-cloudtrail.html), but only the calls
Floci serves are recorded, so only those operations' shapes are vendored (`OPERATIONS`).

GuardDuty's model is a REST-JSON one whose body names its members in camel case (`"detectorId"`,
`"findingPublishingFrequency"`, `"dnsLogs"` for `DNSLogs`), as a record writes them, so the body members are
keyed by that name (`json_names`), and the members it carries in its path and its query are kept with the
structure's `locations`, as Lambda's are. Beside the shape a member names, `location` and `locationName`
(where it travels and under which name), a deprecation and `idempotencyToken` say nothing of how a record
types or redacts a member. Any other stops the generation.

The model is botocore's `guardduty/2017-11-28/` (Apache-2.0, https://github.com/boto/botocore), located, in
order, at `--botocore-data`, the `local/aws/botocore` checkout, then the installed `botocore`
package, which `requirements.txt` pins so CI regenerates the same bytes.

Run from anywhere in the repo:
    python3 tools/aws/regen_guardduty_cloudtrail_shapes.py            # rewrite the vendored file in place
    python3 tools/aws/regen_guardduty_cloudtrail_shapes.py --check    # exit 1 when the vendored file is stale
"""
from __future__ import annotations

import sys
from pathlib import Path

import request_shapes
from request_shapes import REPO_ROOT

OUTPUT = REPO_ROOT / "src/main/resources/aws/guardduty-cloudtrail-shapes.json"
MODEL = Path("guardduty/2017-11-28")

# The GuardDuty calls Floci serves, whose shapes are vendored.
OPERATIONS = (
    "CreateDetector", "CreateMalwareProtectionPlan", "CreateMembers", "CreatePublishingDestination",
    "DeleteDetector", "DeleteMalwareProtectionPlan", "DeletePublishingDestination",
    "DescribeOrganizationConfiguration", "DescribePublishingDestination", "DisableOrganizationAdminAccount",
    "EnableOrganizationAdminAccount", "GetDetector", "GetMalwareProtectionPlan", "ListDetectors",
    "ListMalwareProtectionPlans", "ListMembers", "ListPublishingDestinations", "ListTagsForResource",
    "TagResource", "UntagResource", "UpdateDetector", "UpdateMalwareProtectionPlan",
    "UpdateOrganizationConfiguration", "UpdatePublishingDestination",
)

MEMBER_TRAITS = {"shape", "documentation", "location", "locationName", "deprecated", "deprecatedMessage",
                 "idempotencyToken"}
readable = request_shapes.record_check(MEMBER_TRAITS)


def main(argv: list[str] | None = None) -> int:
    return request_shapes.main(argv, script=__file__, model=MODEL, output=OUTPUT, description=__doc__,
                               results=True, sensitive=True, check=readable, subset=OPERATIONS,
                               located=True, json_names=True)


if __name__ == "__main__":
    sys.exit(main())
