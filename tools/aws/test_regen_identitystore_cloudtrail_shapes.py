"""Tests for regen_identitystore_cloudtrail_shapes: what it keeps of the Identity Store's JSON model for a record.

Run with: pytest tools/aws -q  (or: make aws-data-test)
"""
from __future__ import annotations

import regen_identitystore_cloudtrail_shapes as cloudtrail
import request_shapes as r

GENERATOR = "tools/aws/regen_identitystore_cloudtrail_shapes.py"


def test_an_attribute_value_is_vendored_sensitive_as_the_attributes_it_carries():
    model = cloudtrail.hide_attribute_values({"operations": {
        "UpdateGroup": {"input": {"shape": "UpdateGroupRequest"}},
    }, "shapes": {
        "UpdateGroupRequest": {"type": "structure", "members": {
            "GroupId": {"shape": "String"}, "Operations": {"shape": "AttributeOperations"}}},
        "AttributeOperations": {"type": "list", "member": {"shape": "AttributeOperation"}},
        "AttributeOperation": {"type": "structure", "members": {
            "AttributePath": {"shape": "String"}, "AttributeValue": {"shape": "AttributeValue"}}},
        "AttributeValue": {"type": "structure", "members": {}, "document": True},
        "String": {"type": "string"},
    }})
    document = r.build(model, "botocore test", GENERATOR, results=True, sensitive=True, errors=True,
                       check=cloudtrail.readable, subset=cloudtrail.OPERATIONS)
    assert document["shapes"]["AttributeValue"] == {"type": "structure", "sensitive": True, "members": {}}
    assert document["shapes"]["String"] == {"type": "string"}
