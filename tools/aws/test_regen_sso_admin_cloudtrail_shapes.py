"""Tests for regen_sso_admin_cloudtrail_shapes: what it keeps of SSO Admin's JSON model for a record.

Run with: pytest tools/aws -q  (or: make aws-data-test)
"""
from __future__ import annotations

import regen_sso_admin_cloudtrail_shapes as cloudtrail
import request_shapes as r

GENERATOR = "tools/aws/regen_sso_admin_cloudtrail_shapes.py"


def build(operations: dict) -> dict:
    shapes = {
        "PutRequest": {"type": "structure", "members": {
            "ClientToken": {"shape": "String", "idempotencyToken": True},
            "ActorPolicy": {"shape": "ActorPolicyDocument"}}},
        "ActorPolicyDocument": {"type": "structure", "members": {}, "document": True},
        "String": {"type": "string"},
    }
    return r.build({"operations": operations, "shapes": shapes}, "botocore test", GENERATOR, results=True,
                   sensitive=True, errors=True, check=cloudtrail.readable, subset=cloudtrail.OPERATIONS,
                   documents=True)


def test_a_document_keeps_its_flag_for_the_record_to_write_as_sent():
    document = build({"PutApplicationAuthenticationMethod": {"input": {"shape": "PutRequest"}}})
    assert document["shapes"]["ActorPolicyDocument"] == {"type": "structure", "members": {}, "document": True}
    assert document["shapes"]["PutRequest"]["members"]["ClientToken"] == "String"


def test_only_the_operations_the_guide_lists_are_vendored():
    document = build({"PutApplicationAuthenticationMethod": {"input": {"shape": "PutRequest"}},
                      "PutApplicationSessionConfiguration": {"input": {"shape": "PutRequest"}}})
    assert list(document["operations"]) == ["PutApplicationAuthenticationMethod"]
