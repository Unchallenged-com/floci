"""Tests for regen_sqs_cloudtrail_events.

Run with: pytest tools/aws -q  (or: make aws-data-test)
"""
from __future__ import annotations

import regen_sqs_cloudtrail_events as r


def reference(*actions: tuple[str, dict]) -> dict:
    return {"Actions": [{"Name": name, "Annotations": {"Properties": properties}} for name, properties in actions]}


WRITE = {"IsWrite": True, "IsPermissionManagement": False, "IsTaggingOnly": False}
READ = {"IsWrite": False, "IsPermissionManagement": False, "IsTaggingOnly": False}
REFERENCE = reference(*[(name, READ if name == "ListMessageMoveTasks" else WRITE) for name in r.MANAGEMENT_EVENTS],
                      ("ReceiveMessage", READ), ("GetQueueAttributes", READ))


def test_only_the_guides_management_events_are_listed():
    document = r.build(REFERENCE, "test")
    assert document["managementEvents"] == sorted(r.MANAGEMENT_EVENTS)
    assert "ReceiveMessage" not in document["managementEvents"]


def test_read_only_is_the_references_access_level_among_management_events():
    assert r.build(REFERENCE, "test")["readOnlyActions"] == ["ListMessageMoveTasks"]


def test_a_built_document_is_valid_and_verified():
    document = r.build(REFERENCE, "test")
    assert r.validate(document) == []
    assert r.verify_against(document, REFERENCE) == []


def test_a_read_only_action_that_is_not_a_management_event_is_a_problem():
    document = dict(r.build(REFERENCE, "test"), readOnlyActions=["GetQueueAttributes", "ListMessageMoveTasks"])
    assert any("not a management event" in problem for problem in r.validate(document))


def test_a_write_listed_as_read_only_fails_verification():
    document = dict(r.build(REFERENCE, "test"), readOnlyActions=["DeleteQueue", "ListMessageMoveTasks"])
    assert r.validate(document) != []
    assert r.verify_against(document, REFERENCE) != []


def test_a_management_event_the_reference_does_not_publish_fails_verification():
    published = reference(*[(name, WRITE) for name in r.MANAGEMENT_EVENTS if name != "PurgeQueue"],
                          ("ListMessageMoveTasks", READ))
    assert any("PurgeQueue" in problem for problem in r.verify_against(r.build(REFERENCE, "test"), published))
