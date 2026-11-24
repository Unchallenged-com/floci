"""Tests for regen_route53_cloudtrail_shapes: what it keeps of a REST-XML answer's header, and the body
members it refuses, which the record would misname.

Run with: pytest tools/aws -q  (or: make aws-data-test)
"""
from __future__ import annotations

import pytest

import regen_route53_cloudtrail_shapes as cloudtrail
import request_shapes as r

GENERATOR = "tools/aws/regen_route53_cloudtrail_shapes.py"


def model(body_member: dict) -> dict:
    return {"metadata": {"protocol": "rest-xml"}, "operations": {
        "CreateHostedZone": {"input": {"shape": "CreateHostedZoneRequest"},
                             "output": {"shape": "CreateHostedZoneResponse"}}}, "shapes": {
        "CreateHostedZoneRequest": {"type": "structure", "members": {"Name": body_member}},
        "CreateHostedZoneResponse": {"type": "structure", "members": {
            "Location": {"shape": "name", "location": "header", "locationName": "Location"}}},
        "name": {"type": "string"}}}


def test_an_answers_location_header_is_kept_and_says_where():
    shapes = r.build(model({"shape": "name"}), "botocore test", GENERATOR, results=True,
                     check=cloudtrail.readable, located=True)["shapes"]
    assert shapes["CreateHostedZoneResponse"]["locations"] == {
        "Location": {"location": "header", "name": "Location"}}


def test_a_body_member_renamed_on_the_wire_stops_the_generation():
    with pytest.raises(ValueError, match="renamed in the body"):
        r.build(model({"shape": "name", "locationName": "DomainName"}), "botocore test", GENERATOR,
                results=True, check=cloudtrail.readable, located=True)
