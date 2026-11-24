"""Tests for regen_guardduty_cloudtrail_shapes, and for what request_shapes.build keeps for it: the body
members of a REST-JSON request keyed by the name its JSON gives them.

Run with: pytest tools/aws -q  (or: make aws-data-test)
"""
from __future__ import annotations

import regen_guardduty_cloudtrail_shapes as cloudtrail
import request_shapes as r

GENERATOR = "tools/aws/regen_guardduty_cloudtrail_shapes.py"

MODEL = {"metadata": {"protocol": "rest-json"}, "operations": {
    "UpdateDetector": {"input": {"shape": "UpdateDetectorRequest"}}}, "shapes": {
    "UpdateDetectorRequest": {"type": "structure", "members": {
        "DetectorId": {"shape": "name", "location": "uri", "locationName": "DetectorId"},
        "Enable": {"shape": "flag", "locationName": "enable"},
        "DNSLogs": {"shape": "name", "locationName": "dnsLogs"}}},
    "name": {"type": "string"}, "flag": {"type": "boolean"}}}


def test_a_body_member_is_keyed_by_its_json_name():
    shapes = r.build(MODEL, "botocore test", GENERATOR, results=True, check=cloudtrail.readable,
                     located=True, json_names=True)["shapes"]
    assert shapes["UpdateDetectorRequest"]["members"] == {"DetectorId": "name", "enable": "flag",
                                                          "dnsLogs": "name"}
    assert shapes["UpdateDetectorRequest"]["locations"] == {
        "DetectorId": {"location": "uri", "name": "DetectorId"}}


def test_without_json_names_members_keep_their_model_names():
    shapes = r.build(MODEL, "botocore test", GENERATOR, check=cloudtrail.readable, located=True)["shapes"]
    assert shapes["UpdateDetectorRequest"]["members"] == {"DetectorId": "name", "Enable": "flag",
                                                          "DNSLogs": "name"}

