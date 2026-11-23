#!/usr/bin/env python3
"""Regenerate src/main/resources/aws/cloudwatch-cloudtrail-shapes.json from botocore's CloudWatch model.

CloudTrail records CloudWatch's API calls, and `CloudWatchCloudTrailEvents` writes each record's
`requestParameters` and `responseElements` from the call's request and result. The file is
`request_shapes.build`'s, as IAM's (`regen_iam_cloudtrail_shapes.py`): each operation's input shape,
its result shape, every shape they reach with its type and the `sensitive` flag, and every error
CloudWatch models, from the code it answers with to its shape's name.

CloudWatch's management events are the calls its guide lists, its other calls (PutMetricData,
GetMetricData, ...) being data events, so only those operations' shapes are vendored (`OPERATIONS`).

Two of the model's error shapes answer one code (DashboardNotFoundError and ResourceNotFound both
answer ResourceNotFound); a record keeps the code answered, which names neither shape, so that code
is left out of `errors` rather than mapped to one of them. Beside the shape a member names, a
deprecation, `box` and `idempotencyToken` say nothing of how a record names, types or redacts a
member. Any other stops the generation.

The model is botocore's `cloudwatch/2010-08-01/` (Apache-2.0, https://github.com/boto/botocore), located, in
order, at `--botocore-data`, the `local/aws/botocore` checkout, then the installed `botocore`
package, which `requirements.txt` pins so CI regenerates the same bytes.

Run from anywhere in the repo:
    python3 tools/aws/regen_cloudwatch_cloudtrail_shapes.py            # rewrite the vendored file in place
    python3 tools/aws/regen_cloudwatch_cloudtrail_shapes.py --check    # exit 1 when the vendored file is stale
"""
from __future__ import annotations

import sys
from pathlib import Path

import request_shapes
from request_shapes import REPO_ROOT

OUTPUT = REPO_ROOT / "src/main/resources/aws/cloudwatch-cloudtrail-shapes.json"
MODEL = Path("cloudwatch/2010-08-01")

# The calls the CloudWatch guide lists as management events, whose shapes are vendored.
OPERATIONS = (
    "DeleteAlarms", "DeleteAnomalyDetector", "DeleteDashboards", "DeleteInsightRules",
    "DeleteMetricDataQueryDefinition", "DeleteMetricStream", "DescribeAlarmHistory", "DescribeAlarms",
    "DescribeAlarmsForMetric", "DescribeAnomalyDetectors", "DescribeInsightRules", "DisableAlarmActions",
    "DisableInsightRules", "EnableAlarmActions", "EnableInsightRules", "GetDashboard",
    "GetInsightRuleReport", "GetMetricDataQueryDefinition", "GetMetricStream", "ListDashboards",
    "ListManagedInsightRules", "ListMetricDataQueryDefinitions", "ListMetricStreams",
    "ListTagsForResource", "PutAnomalyDetector", "PutCompositeAlarm", "PutDashboard", "PutInsightRule",
    "PutLogAlarm", "PutManagedInsightRules", "PutMetricAlarm", "PutMetricDataQueryDefinition",
    "PutMetricStream", "SetAlarmState", "StartMetricStreams", "StopMetricStreams", "TagResource",
    "UntagResource",
)

MEMBER_TRAITS = {"shape", "documentation", "deprecated", "deprecatedMessage", "box", "idempotencyToken"}
readable = request_shapes.record_check(MEMBER_TRAITS)


def main(argv: list[str] | None = None) -> int:
    return request_shapes.main(argv, script=__file__, model=MODEL, output=OUTPUT, description=__doc__,
                               results=True, sensitive=True, errors=True, check=readable,
                               subset=OPERATIONS, ambiguous_errors_dropped=True)


if __name__ == "__main__":
    sys.exit(main())
