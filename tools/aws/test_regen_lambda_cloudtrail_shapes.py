"""Tests for regen_lambda_cloudtrail_shapes, and for what request_shapes.build keeps for it: the members
a REST-JSON request carries in its path and its query, with where each travels.

Run with: pytest tools/aws -q  (or: make aws-data-test)
"""
from __future__ import annotations

import regen_lambda_cloudtrail_shapes as cloudtrail
import request_shapes as r

GENERATOR = "tools/aws/regen_lambda_cloudtrail_shapes.py"

MODEL = {"metadata": {"protocol": "rest-json"}, "operations": {
    "GetFunction": {"input": {"shape": "GetFunctionRequest"}}}, "shapes": {
    "GetFunctionRequest": {"type": "structure", "members": {
        "FunctionName": {"shape": "name", "location": "uri", "locationName": "FunctionName"},
        "Qualifier": {"shape": "name", "location": "querystring", "locationName": "Qualifier"},
        "Body": {"shape": "name"}}},
    "name": {"type": "string"}}}


def test_a_member_carried_in_the_path_or_the_query_is_kept_and_says_where():
    shapes = r.build(MODEL, "botocore test", GENERATOR, results=True, check=cloudtrail.readable,
                     located=True)["shapes"]
    assert shapes["GetFunctionRequest"]["members"] == {"FunctionName": "name", "Qualifier": "name", "Body": "name"}
    assert shapes["GetFunctionRequest"]["locations"] == {
        "FunctionName": {"location": "uri", "name": "FunctionName"},
        "Qualifier": {"location": "querystring", "name": "Qualifier"}}


def test_without_located_such_members_are_left_out_as_before():
    shapes = r.build(MODEL, "botocore test", GENERATOR, check=cloudtrail.readable)["shapes"]
    assert shapes["GetFunctionRequest"] == {"type": "structure", "members": {"Body": "name"}}
