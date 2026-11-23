"""Tests for regen_sqs_cloudtrail_shapes: which member traits of SQS's JSON model the record reads.

Run with: pytest tools/aws -q  (or: make aws-data-test)
"""
from __future__ import annotations

import pytest

import regen_sqs_cloudtrail_shapes as cloudtrail
import request_shapes as r

GENERATOR = "tools/aws/regen_sqs_cloudtrail_shapes.py"

OPERATIONS = {
    "ListQueueTags": {"input": {"shape": "ListQueueTagsRequest"},
                      "output": {"shape": "ListQueueTagsResult"}},
}


def build(request: dict) -> dict:
    shapes = {
        "ListQueueTagsRequest": request,
        "ListQueueTagsResult": {"type": "structure", "members": {"Tags": {"shape": "TagMap"}}},
        "TagMap": {"type": "map", "key": {"shape": "String"}, "value": {"shape": "String"},
                   "flattened": True},
        "String": {"type": "string"},
    }
    return r.build({"operations": OPERATIONS, "shapes": shapes}, "botocore test", GENERATOR,
                   results=True, sensitive=True, errors=True, check=cloudtrail.readable)


def test_flattened_and_deprecated_members_are_read_as_plain_ones():
    document = build({"type": "structure", "members": {
        "QueueUrl": {"shape": "String", "flattened": True},
        "Owner": {"shape": "String", "deprecated": True, "deprecatedMessage": "Use another."}}})
    assert document["shapes"]["ListQueueTagsRequest"] == {
        "type": "structure", "members": {"QueueUrl": "String", "Owner": "String"}}
    assert document["results"]["ListQueueTags"] == {"shape": "ListQueueTagsResult", "resultWrapper": None}


def test_a_member_renamed_on_the_wire_stops_the_generation():
    with pytest.raises(ValueError, match="locationName"):
        build({"type": "structure", "members": {"QueueUrl": {"shape": "String", "locationName": "url"}}})
