"""Tests for regen_ec2_cloudtrail_shapes, and for what request_shapes.build keeps for it: the operations
it names alone, and each result's members under their XML names.

Run with: pytest tools/aws -q  (or: make aws-data-test)
"""
from __future__ import annotations

import regen_ec2_cloudtrail_shapes as cloudtrail
import request_shapes as r

GENERATOR = "tools/aws/regen_ec2_cloudtrail_shapes.py"

SHAPES = {
    "StartInstancesRequest": {"type": "structure", "members": {
        "InstanceIds": {"shape": "InstanceIdStringList", "locationName": "InstanceId", "queryName": "InstanceId"}}},
    "StartInstancesResult": {"type": "structure", "members": {
        "StartingInstances": {"shape": "InstanceStateChangeList", "locationName": "instancesSet"}}},
    "InstanceStateChangeList": {"type": "list", "member": {"shape": "InstanceStateChange", "locationName": "item"}},
    "InstanceStateChange": {"type": "structure", "members": {
        "InstanceId": {"shape": "String", "locationName": "instanceId"}}},
    "InstanceIdStringList": {"type": "list", "member": {"shape": "String", "locationName": "InstanceId"}},
    "DescribeRegionsResult": {"type": "structure", "members": {"Regions": {"shape": "String"}}},
    "String": {"type": "string"},
}
OPERATIONS = {
    "StartInstances": {"input": {"shape": "StartInstancesRequest"}, "output": {"shape": "StartInstancesResult"}},
    "DescribeRegions": {"output": {"shape": "DescribeRegionsResult"}},
}


def build() -> dict:
    return r.build({"operations": OPERATIONS, "shapes": SHAPES}, "botocore test", GENERATOR, results=True,
                   sensitive=True, errors=True, check=cloudtrail.readable, subset=("StartInstances",),
                   xml_names=True)


def test_only_the_operations_named_are_kept():
    document = build()
    assert list(document["results"]) == ["StartInstances"]
    assert "DescribeRegionsResult" not in document["shapes"]


def test_a_result_names_its_members_as_its_xml_does_and_no_request_is_vendored():
    document = build()
    assert document["shapes"]["StartInstancesResult"] == {
        "type": "structure", "members": {"instancesSet": "InstanceStateChangeList"}}
    assert document["shapes"]["InstanceStateChange"]["members"] == {"instanceId": "String"}
    assert document["operations"] == {"StartInstances": "StartInstancesRequest"}
    assert "StartInstancesRequest" not in document["shapes"]


def test_without_them_every_operation_is_kept_under_its_model_names():
    document = r.build({"operations": OPERATIONS, "shapes": SHAPES}, "botocore test", GENERATOR, results=True,
                       check=cloudtrail.readable)
    assert set(document["results"]) == {"StartInstances", "DescribeRegions"}
    assert document["shapes"]["StartInstancesResult"]["members"] == {"StartingInstances": "InstanceStateChangeList"}
