"""Tests for regen_account_cloudtrail_shapes: what it keeps of Account's REST-JSON model for a record.

Run with: pytest tools/aws -q  (or: make aws-data-test)
"""
from __future__ import annotations

import pytest

import regen_account_cloudtrail_shapes as cloudtrail
import request_shapes as r

GENERATOR = "tools/aws/regen_account_cloudtrail_shapes.py"


def build(request: dict) -> dict:
    model = {"metadata": {"protocol": "rest-json"}, "operations": {
        "PutAlternateContact": {"input": {"shape": "PutAlternateContactRequest"}},
        "SendPhoneNumberVerification": {"input": {"shape": "PutAlternateContactRequest"}},
    }, "shapes": {
        "PutAlternateContactRequest": request,
        "PhoneNumber": {"type": "string", "sensitive": True},
        "AlternateContactType": {"type": "string"},
    }}
    return r.build(model, "botocore test", GENERATOR, results=True, sensitive=True, errors=True,
                   check=cloudtrail.readable, subset=cloudtrail.OPERATIONS)


def test_the_served_calls_are_vendored_with_their_sensitive_members_flagged():
    document = build({"type": "structure", "members": {"PhoneNumber": {"shape": "PhoneNumber"},
                                                       "AlternateContactType": {"shape": "AlternateContactType"}}})
    assert list(document["operations"]) == ["PutAlternateContact"]
    assert document["shapes"]["PhoneNumber"] == {"type": "string", "sensitive": True}


def test_a_member_carried_outside_the_body_stops_the_generation():
    with pytest.raises(ValueError, match="location"):
        build({"type": "structure", "members": {
            "AlternateContactType": {"shape": "AlternateContactType", "location": "header",
                                     "locationName": "x-amz-type"}}})
