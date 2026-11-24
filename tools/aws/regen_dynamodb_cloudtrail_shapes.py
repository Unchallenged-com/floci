#!/usr/bin/env python3
"""Regenerate src/main/resources/aws/dynamodb-cloudtrail-shapes.json from botocore's DynamoDB model.

CloudTrail records DynamoDB's control plane calls, and `DynamoDbCloudTrailEvents` writes each record's
`requestParameters` and `responseElements` from the call's request and result. The file is
`request_shapes.build`'s, as CloudWatch Logs' (`regen_logs_cloudtrail_shapes.py`): each operation's input
shape, its result shape, every shape they reach with its type and the `sensitive` flag, and every error
DynamoDB models, from the code it answers with to its shape's name.

Only the calls recorded as management events are vendored (`OPERATIONS`), as `regen_cloudtrail_events.py`
lists them for the service, without the DynamoDB Streams ones, whose model is another
(`regen_dynamodbstreams_cloudtrail_shapes.py`).

DynamoDB's model is a JSON one. Beside the shape a member names, these member traits say nothing of how a
record names, types or redacts it: `contextParam`, which only says the endpoint rules read the member, and
`idempotencyToken`, which only says an SDK fills the member in when the caller does not. Any other stops
the generation.

The model is botocore's `dynamodb/2012-08-10/` (Apache-2.0, https://github.com/boto/botocore), located, in
order, at `--botocore-data`, the `local/aws/botocore` checkout, then the installed `botocore`
package, which `requirements.txt` pins so CI regenerates the same bytes.

Run from anywhere in the repo:
    python3 tools/aws/regen_dynamodb_cloudtrail_shapes.py            # rewrite the vendored file in place
    python3 tools/aws/regen_dynamodb_cloudtrail_shapes.py --check    # exit 1 when the vendored file is stale
"""
from __future__ import annotations

import sys
from pathlib import Path

import request_shapes
from request_shapes import REPO_ROOT

OUTPUT = REPO_ROOT / "src/main/resources/aws/dynamodb-cloudtrail-shapes.json"
MODEL = Path("dynamodb/2012-08-10")

# The DynamoDB calls recorded as management events, whose shapes are vendored: the guide's list, then the
# other calls Floci serves that its data plane list leaves out.
OPERATIONS = (
    "CreateBackup", "CreateGlobalTable", "CreateTable", "DeleteBackup", "DeleteTable", "DescribeBackup",
    "DescribeContinuousBackups", "DescribeGlobalTable", "DescribeLimits", "DescribeTable",
    "DescribeTimeToLive", "ListBackups", "ListGlobalTables", "ListTables", "ListTagsOfResource",
    "RestoreTableFromBackup", "RestoreTableToPointInTime", "TagResource", "UntagResource",
    "UpdateGlobalTable", "UpdateTable", "UpdateTimeToLive",
    "DeleteResourcePolicy", "DescribeContributorInsights", "DescribeEndpoints", "DescribeExport",
    "DescribeImport", "DescribeKinesisStreamingDestination", "DisableKinesisStreamingDestination",
    "EnableKinesisStreamingDestination", "ExportTableToPointInTime", "GetResourcePolicy", "ImportTable",
    "ListContributorInsights", "ListExports", "ListImports", "PutResourcePolicy", "UpdateContinuousBackups",
    "UpdateContributorInsights", "UpdateKinesisStreamingDestination",
)

MEMBER_TRAITS = {"shape", "documentation", "contextParam", "idempotencyToken"}
readable = request_shapes.record_check(MEMBER_TRAITS)


def main(argv: list[str] | None = None) -> int:
    return request_shapes.main(argv, script=__file__, model=MODEL, output=OUTPUT, description=__doc__,
                               results=True, sensitive=True, errors=True, check=readable, subset=OPERATIONS)


if __name__ == "__main__":
    sys.exit(main())
