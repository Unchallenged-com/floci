"""Tests for regen_rds_cloudtrail_shapes, and for what request_shapes.build keeps for it: the name a
list's model gives its members, under which a Query request numbers them.

Run with: pytest tools/aws -q  (or: make aws-data-test)
"""
from __future__ import annotations

import regen_rds_cloudtrail_shapes as cloudtrail
import request_shapes as r

GENERATOR = "tools/aws/regen_rds_cloudtrail_shapes.py"

MODEL = {"operations": {"ModifyDBSnapshotAttribute": {"input": {"shape": "ModifyDBSnapshotAttributeMessage"}}},
         "shapes": {
             "ModifyDBSnapshotAttributeMessage": {"type": "structure", "members": {
                 "ValuesToAdd": {"shape": "AttributeValueList"},
                 "EnableCloudwatchLogsExports": {"shape": "LogTypeList"},
                 "MasterUserPassword": {"shape": "SensitiveString"}}},
             "AttributeValueList": {"type": "list", "member": {"shape": "String", "locationName": "AttributeValue"}},
             "LogTypeList": {"type": "list", "member": {"shape": "String"}},
             "SensitiveString": {"type": "string", "sensitive": True},
             "String": {"type": "string"}}}


def test_a_list_keeps_the_name_its_model_gives_its_members():
    shapes = r.build(MODEL, "botocore test", GENERATOR, sensitive=True, check=cloudtrail.readable,
                     list_member_names=True)["shapes"]
    assert shapes["AttributeValueList"] == {"type": "list", "member": "String", "memberName": "AttributeValue"}
    assert shapes["LogTypeList"] == {"type": "list", "member": "String"}
    assert shapes["SensitiveString"] == {"type": "string", "sensitive": True}


def test_without_the_option_no_member_name_is_kept():
    shapes = r.build(MODEL, "botocore test", GENERATOR, check=cloudtrail.readable)["shapes"]
    assert "memberName" not in shapes["AttributeValueList"]
