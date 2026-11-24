"""Tests for regen_dynamodb_cloudtrail_shapes and regen_dynamodbstreams_cloudtrail_shapes: together, the
shapes they vendor are those of the calls the CloudTrail catalog records for DynamoDB, no more and no fewer.

Run with: pytest tools/aws -q  (or: make aws-data-test)
"""
from __future__ import annotations

import regen_cloudtrail_events as events
import regen_dynamodb_cloudtrail_shapes as dynamodb
import regen_dynamodbstreams_cloudtrail_shapes as streams


def test_the_vendored_operations_are_the_recorded_management_events():
    assert sorted(dynamodb.OPERATIONS + streams.OPERATIONS) == sorted(events.SERVICES["dynamodb"].management_events)


def test_no_operation_is_vendored_from_both_models():
    assert set(dynamodb.OPERATIONS).isdisjoint(streams.OPERATIONS)
