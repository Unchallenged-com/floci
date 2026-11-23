"""Tests for regen_cloudtrail_events.

Run with: pytest tools/aws -q  (or: make aws-data-test)
"""
from __future__ import annotations

import pytest

import regen_cloudtrail_events as r


def reference(*actions: tuple[str, dict]) -> dict:
    return {"Actions": [{"Name": name, "Annotations": {"Properties": properties}} for name, properties in actions]}


WRITE = {"IsWrite": True, "IsPermissionManagement": False, "IsTaggingOnly": False}
READ = {"IsWrite": False, "IsPermissionManagement": False, "IsTaggingOnly": False}
SQS = r.SERVICES["sqs"].management_events
SQS_REFERENCE = reference(*[(name, READ if name == "ListMessageMoveTasks" else WRITE) for name in SQS],
                          ("ReceiveMessage", READ), ("GetQueueAttributes", READ))
SECRETS_READS = {"BatchGetSecretValue", "DescribeSecret", "GetRandomPassword", "GetResourcePolicy",
                 "GetSecretValue", "ListSecretVersionIds", "ListSecrets"}
SECRETS_REFERENCE = reference(*[(name, READ if name in SECRETS_READS else WRITE)
                                for name in r.SERVICES["secretsmanager"].management_events])


def test_only_the_guides_management_events_are_listed():
    document = r.build("sqs", SQS_REFERENCE, "test")
    assert document["managementEvents"] == sorted(SQS)
    assert "ReceiveMessage" not in document["managementEvents"]


def test_read_only_is_the_references_access_level_among_management_events():
    assert r.build("sqs", SQS_REFERENCE, "test")["readOnlyActions"] == ["ListMessageMoveTasks"]
    assert r.build("secretsmanager", SECRETS_REFERENCE, "test")["readOnlyActions"] == sorted(SECRETS_READS)


@pytest.mark.parametrize("service,published", [("sqs", SQS_REFERENCE), ("secretsmanager", SECRETS_REFERENCE)])
def test_a_built_document_is_valid_and_verified(service, published):
    document = r.build(service, published, "test")
    assert r.validate(service, document) == []
    assert r.verify_against(service, document, published) == []


def test_each_service_is_written_to_its_own_file():
    assert r.output_for("secretsmanager").name == "secretsmanager-cloudtrail-events.json"
    assert r.output_for("sqs").name == "sqs-cloudtrail-events.json"


def test_a_read_only_action_that_is_not_a_management_event_is_a_problem():
    document = dict(r.build("sqs", SQS_REFERENCE, "test"), readOnlyActions=["GetQueueAttributes", "ListMessageMoveTasks"])
    assert any("not a management event" in problem for problem in r.validate("sqs", document))


def test_a_write_listed_as_read_only_fails_verification():
    document = dict(r.build("sqs", SQS_REFERENCE, "test"), readOnlyActions=["DeleteQueue", "ListMessageMoveTasks"])
    assert r.validate("sqs", document) != []
    assert r.verify_against("sqs", document, SQS_REFERENCE) != []


def test_a_secret_read_listed_as_a_write_is_a_problem():
    document = r.build("secretsmanager", SECRETS_REFERENCE, "test")
    document["readOnlyActions"] = [name for name in document["readOnlyActions"] if name != "GetSecretValue"]
    assert any("GetSecretValue" in problem for problem in r.validate("secretsmanager", document))


def test_a_management_event_the_reference_does_not_publish_fails_verification():
    published = reference(*[(name, WRITE) for name in SQS if name != "PurgeQueue"],
                          ("ListMessageMoveTasks", READ))
    assert any("PurgeQueue" in problem
               for problem in r.verify_against("sqs", r.build("sqs", SQS_REFERENCE, "test"), published))


def test_a_call_the_guide_shows_read_only_is_read_only_whatever_its_access_level():
    kms = r.SERVICES["kms"]
    published = reference(*[(action, READ if name.startswith(("List", "Describe", "Get")) else WRITE)
                            for name in kms.management_events
                            for action in kms.reference_actions.get(name, (name,))])
    document = r.build("kms", published, "test")
    assert "Decrypt" in document["readOnlyActions"]
    assert "GenerateRandom" in document["readOnlyActions"]
    assert "ScheduleKeyDeletion" not in document["readOnlyActions"]
    assert r.validate("kms", document) == []
    assert r.verify_against("kms", document, published) == []


def test_a_call_authorized_under_other_actions_is_verified_against_them():
    kms = r.SERVICES["kms"]
    published = reference(*[(name, WRITE) for name in kms.management_events])
    document = r.build("kms", published, "test")
    assert any("'ReEncrypt'" in problem for problem in r.verify_against("kms", document, published))
