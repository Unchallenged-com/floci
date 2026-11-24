#!/usr/bin/env python3
"""Regenerate src/main/resources/aws/dynamodbstreams-cloudtrail-shapes.json from botocore's DynamoDB Streams
model.

CloudTrail records the DynamoDB Streams calls the DynamoDB guide lists as control plane events
(`DescribeStream`, `ListStreams`), and `DynamoDbCloudTrailEvents` writes each record's `requestParameters`
from the call's request. The file is `request_shapes.build`'s, as DynamoDB's
(`regen_dynamodb_cloudtrail_shapes.py`), for those calls alone (`OPERATIONS`): `GetRecords` and
`GetShardIterator` are data events.

DynamoDB Streams' model is a JSON one. Beside the shape a member names, `contextParam`, which only says the
endpoint rules read the member, says nothing of how a record names, types or redacts it. Any other stops
the generation.

The model is botocore's `dynamodbstreams/2012-08-10/` (Apache-2.0, https://github.com/boto/botocore),
located, in order, at `--botocore-data`, the `local/aws/botocore` checkout, then the installed `botocore`
package, which `requirements.txt` pins so CI regenerates the same bytes.

Run from anywhere in the repo:
    python3 tools/aws/regen_dynamodbstreams_cloudtrail_shapes.py            # rewrite the vendored file in place
    python3 tools/aws/regen_dynamodbstreams_cloudtrail_shapes.py --check    # exit 1 when the vendored file is stale
"""
from __future__ import annotations

import sys
from pathlib import Path

import request_shapes
from request_shapes import REPO_ROOT

OUTPUT = REPO_ROOT / "src/main/resources/aws/dynamodbstreams-cloudtrail-shapes.json"
MODEL = Path("dynamodbstreams/2012-08-10")

# The DynamoDB Streams calls the DynamoDB guide lists as management events, whose shapes are vendored.
OPERATIONS = ("DescribeStream", "ListStreams")

MEMBER_TRAITS = {"shape", "documentation", "contextParam"}
readable = request_shapes.record_check(MEMBER_TRAITS)


def main(argv: list[str] | None = None) -> int:
    return request_shapes.main(argv, script=__file__, model=MODEL, output=OUTPUT, description=__doc__,
                               results=True, sensitive=True, errors=True, check=readable, subset=OPERATIONS)


if __name__ == "__main__":
    sys.exit(main())
