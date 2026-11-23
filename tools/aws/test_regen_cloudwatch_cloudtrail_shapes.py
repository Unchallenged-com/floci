"""Tests for regen_cloudwatch_cloudtrail_shapes, and for what request_shapes.build keeps for it: a code
two error shapes answer is left out rather than stopping the generation.

Run with: pytest tools/aws -q  (or: make aws-data-test)
"""
from __future__ import annotations

import pytest

import regen_cloudwatch_cloudtrail_shapes as cloudtrail
import request_shapes as r

GENERATOR = "tools/aws/regen_cloudwatch_cloudtrail_shapes.py"

MODEL = {"operations": {"GetDashboard": {"input": {"shape": "GetDashboardInput"}}}, "shapes": {
    "GetDashboardInput": {"type": "structure", "members": {"DashboardName": {"shape": "name"}}},
    "name": {"type": "string"},
    "DashboardNotFoundError": {"type": "structure", "members": {}, "exception": True,
                               "error": {"code": "ResourceNotFound", "httpStatusCode": 404}},
    "ResourceNotFound": {"type": "structure", "members": {}, "exception": True,
                         "error": {"code": "ResourceNotFound", "httpStatusCode": 404}},
    "LimitExceededFault": {"type": "structure", "members": {}, "exception": True,
                           "error": {"code": "LimitExceeded"}}}}


def test_a_code_two_errors_answer_is_left_out():
    errors = r.build(MODEL, "botocore test", GENERATOR, errors=True, check=cloudtrail.readable,
                     ambiguous_errors_dropped=True)["errors"]
    assert errors == {"LimitExceeded": "LimitExceededFault"}


def test_without_the_option_it_stops_the_generation():
    with pytest.raises(ValueError, match="both answer ResourceNotFound"):
        r.build(MODEL, "botocore test", GENERATOR, errors=True, check=cloudtrail.readable)
