"""Tests for regen_organizations_cloudtrail_shapes: what it keeps of Organizations' JSON model for a record.

Run with: pytest tools/aws -q  (or: make aws-data-test)
"""
from __future__ import annotations

import pytest

import regen_organizations_cloudtrail_shapes as cloudtrail
import request_shapes as r

GENERATOR = "tools/aws/regen_organizations_cloudtrail_shapes.py"


def build(request: dict, operations: dict | None = None) -> dict:
    shapes = {
        "CreateAccountRequest": request,
        "CreateAccountResponse": {"type": "structure", "members": {"Id": {"shape": "String"}}},
        "Email": {"type": "string", "sensitive": True},
        "String": {"type": "string"},
    }
    model = {"operations": operations or {
        "CreateAccount": {"input": {"shape": "CreateAccountRequest"}, "output": {"shape": "CreateAccountResponse"}},
        "ListRoots": {"input": {"shape": "CreateAccountRequest"}},
    }, "shapes": shapes}
    return r.build(model, "botocore test", GENERATOR, results=True, sensitive=True, errors=True,
                   check=cloudtrail.readable, subset=cloudtrail.OPERATIONS)


def test_a_sensitive_member_keeps_its_flag_for_the_record_to_mask():
    document = build({"type": "structure", "members": {"Email": {"shape": "Email"},
                                                       "AccountName": {"shape": "String"}}})
    assert document["shapes"]["Email"] == {"type": "string", "sensitive": True}
    assert document["operations"]["CreateAccount"] == "CreateAccountRequest"


def test_only_the_calls_floci_serves_are_vendored():
    document = build({"type": "structure", "members": {"Email": {"shape": "Email"}}}, operations={
        "CreateAccount": {"input": {"shape": "CreateAccountRequest"}},
        "InviteOrganizationToTransferResponsibility": {"input": {"shape": "CreateAccountRequest"}},
    })
    assert list(document["operations"]) == ["CreateAccount"]


def test_a_member_trait_the_record_does_not_read_stops_the_generation():
    with pytest.raises(ValueError, match="locationName"):
        build({"type": "structure", "members": {"Email": {"shape": "Email", "locationName": "email"}}})
