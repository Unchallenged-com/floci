"""Tests for regen_sts_cloudtrail_shapes: what request_shapes.build keeps of STS's model for a
CloudTrail record.

Run with: pytest tools/aws -q  (or: make aws-data-test)
"""
from __future__ import annotations

import pytest

import regen_sts_cloudtrail_shapes as cloudtrail
import request_shapes as r

GENERATOR = "tools/aws/regen_sts_cloudtrail_shapes.py"

SHAPES = {
    "AssumeRoleRequest": {"type": "structure", "members": {
        "RoleArn": {"shape": "arnType"}, "TokenCode": {"shape": "tokenCodeType"}}},
    "AssumeRoleResponse": {"type": "structure", "members": {
        "Credentials": {"shape": "Credentials"},
        "PackedPolicySize": {"shape": "nonNegativeIntegerType", "deprecated": True,
                             "deprecatedMessage": "Use SessionTokenUtilization.", "deprecatedSince": "2026-06-17"},
        "SessionTokenSize": {"shape": "sessionTokenSizeType"}}},
    "Credentials": {"type": "structure", "members": {
        "AccessKeyId": {"shape": "accessKeyIdType"}, "SecretAccessKey": {"shape": "accessKeySecretType"},
        "Expiration": {"shape": "dateType"}}},
    "arnType": {"type": "string"},
    "tokenCodeType": {"type": "string"},
    "accessKeyIdType": {"type": "string"},
    "accessKeySecretType": {"type": "string", "sensitive": True},
    "dateType": {"type": "timestamp"},
    "nonNegativeIntegerType": {"type": "integer"},
    "sessionTokenSizeType": {"type": "integer"},
    "ExpiredTokenException": {"type": "structure", "members": {}, "exception": True,
                              "error": {"code": "ExpiredTokenException"}},
}
OPERATIONS = {
    "AssumeRole": {"input": {"shape": "AssumeRoleRequest"},
                   "output": {"shape": "AssumeRoleResponse", "resultWrapper": "AssumeRoleResult"}},
}


def build(shapes: dict = SHAPES) -> dict:
    return r.build({"operations": OPERATIONS, "shapes": shapes}, "botocore test", GENERATOR,
                   results=True, sensitive=True, check=cloudtrail.readable)


def test_a_deprecated_member_is_kept_as_it_is():
    assert build()["shapes"]["AssumeRoleResponse"]["members"]["PackedPolicySize"] == "nonNegativeIntegerType"


def test_the_secret_access_key_is_marked_sensitive():
    assert build()["shapes"]["accessKeySecretType"] == {"type": "string", "sensitive": True}


def test_each_result_names_its_shape_and_wrapper():
    assert build()["results"] == {"AssumeRole": {"shape": "AssumeRoleResponse", "resultWrapper": "AssumeRoleResult"}}


def test_no_error_table_is_kept():
    assert "errors" not in build()


def test_a_member_trait_the_record_does_not_read_stops_the_generation():
    shapes = dict(SHAPES, Credentials={"type": "structure", "members": {
        "AccessKeyId": {"shape": "accessKeyIdType", "locationName": "keyId"}}})
    with pytest.raises(ValueError, match="locationName"):
        build(shapes)
