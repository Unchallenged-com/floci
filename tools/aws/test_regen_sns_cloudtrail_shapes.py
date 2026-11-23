"""Tests for regen_sns_cloudtrail_shapes: only the management events' shapes are vendored, a sensitive
phone number stays marked, and a member trait the record does not read stops the generation.

Run with: pytest tools/aws -q  (or: make aws-data-test)
"""
from __future__ import annotations

import pytest

import regen_sns_cloudtrail_shapes as cloudtrail
import request_shapes as r

GENERATOR = "tools/aws/regen_sns_cloudtrail_shapes.py"


def model(subscribe: dict) -> dict:
    return {"operations": {
        "Subscribe": {"input": {"shape": "SubscribeInput"},
                      "output": {"shape": "SubscribeResponse", "resultWrapper": "SubscribeResult"}},
        "OptInPhoneNumber": {"input": {"shape": "OptInPhoneNumberInput"}},
        "Publish": {"input": {"shape": "PublishInput"}}}, "shapes": {
        "SubscribeInput": subscribe,
        "SubscribeResponse": {"type": "structure", "members": {"SubscriptionArn": {"shape": "String"}}},
        "OptInPhoneNumberInput": {"type": "structure", "members": {"phoneNumber": {"shape": "PhoneNumber"}}},
        "PublishInput": {"type": "structure", "members": {"Message": {"shape": "String"}}},
        "PhoneNumber": {"type": "string", "sensitive": True},
        "String": {"type": "string"}}}


SUBSCRIBE = {"type": "structure", "members": {"TopicArn": {"shape": "String"}, "Endpoint": {"shape": "String"}}}


def build(subscribe: dict) -> dict:
    return r.build(model(subscribe), "botocore test", GENERATOR, results=True, sensitive=True, errors=True,
                   check=cloudtrail.readable, subset=("Subscribe", "OptInPhoneNumber"))


def test_only_the_management_events_are_vendored():
    document = build(SUBSCRIBE)
    assert sorted(document["operations"]) == ["OptInPhoneNumber", "Subscribe"]
    assert "PublishInput" not in document["shapes"]
    assert document["results"]["Subscribe"] == {"shape": "SubscribeResponse", "resultWrapper": "SubscribeResult"}


def test_a_phone_number_stays_sensitive():
    assert build(SUBSCRIBE)["shapes"]["PhoneNumber"] == {"type": "string", "sensitive": True}


def test_the_data_events_are_not_listed():
    assert "Publish" not in cloudtrail.OPERATIONS
    assert "PublishBatch" not in cloudtrail.OPERATIONS


def test_a_member_renamed_on_the_wire_stops_the_generation():
    with pytest.raises(ValueError, match="locationName"):
        build({"type": "structure", "members": {"TopicArn": {"shape": "String", "locationName": "arn"}}})
