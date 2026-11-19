#!/usr/bin/env python3
"""Regenerate src/main/resources/aws/sqs-cloudtrail-events.json: which SQS calls CloudTrail records
as management events, and which of them are read-only.

Which calls are management events is the SQS Developer Guide's, which no machine-readable source
carries, so it stays in MANAGEMENT_EVENTS below, as the guide lists them
(https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/logging-using-cloudtrail.html):
"Amazon SQS logs the following control plane operations to CloudTrail as management events". Every
other SQS call (sending, receiving and deleting messages, and reading a queue's URL, attributes and
tags) is a data event of the `AWS::SQS::Queue` resource type, which a trail logs only when an
advanced event selector selects it.

Which of them are read-only is the access level AWS's Service Reference gives each action, read as
`regen_iam_action_resources.py` reads IAM's: an action with none of the Write, Permissions
management or Tagging properties is one CloudTrail "considers ... read-only"
(https://servicereference.us-east-1.amazonaws.com/v1/sqs/sqs.json). That endpoint is live, so a
fresh generation can differ from the vendored file only when AWS changes an access level:

- `--check` is offline and structural: the file lists exactly MANAGEMENT_EVENTS, sorted, and its
  read-only actions are among them, `ListMessageMoveTasks` included and `DeleteQueue` not.
- `--verify` needs the network: every management event is an action the reference publishes, and
  the read-only list is the one the reference gives.

Run from anywhere in the repo:
    python3 tools/aws/regen_sqs_cloudtrail_events.py           # rewrite the vendored file in place
    python3 tools/aws/regen_sqs_cloudtrail_events.py --check   # offline: shape of the vendored file
    python3 tools/aws/regen_sqs_cloudtrail_events.py --verify  # online: the access levels are AWS's (2: unreachable)
    python3 tools/aws/regen_sqs_cloudtrail_events.py --source <file>  # read a saved copy instead
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from regen_iam_action_resources import read_only_actions_from

REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT = REPO_ROOT / "src/main/resources/aws/sqs-cloudtrail-events.json"
REFERENCE_URL = "https://servicereference.us-east-1.amazonaws.com/v1/sqs/sqs.json"
FETCH_TIMEOUT_SECONDS = 30

# The SQS Developer Guide's list of the calls CloudTrail logs as management events.
MANAGEMENT_EVENTS = (
    "AddPermission",
    "CancelMessageMoveTask",
    "CreateQueue",
    "DeleteQueue",
    "ListMessageMoveTasks",
    "PurgeQueue",
    "RemovePermission",
    "SetQueueAttributes",
    "StartMessageMoveTask",
    "TagQueue",
    "UntagQueue",
)

# Read-only or not, whichever way the reference says, for a listing and a write the file must carry.
READ_ONLY_ANCHORS = {
    "ListMessageMoveTasks": True,
    "DeleteQueue": False,
}


def fetch_reference(source: Path | None) -> tuple[dict, str]:
    """AWS's SQS service reference and a provenance label for where it came from."""
    if source is not None:
        return json.loads(source.read_text(encoding="utf-8")), f"--source {source}"
    request = urllib.request.Request(REFERENCE_URL, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
        payload = response.read().decode("utf-8")
    return json.loads(payload), REFERENCE_URL


def build(reference: dict, provenance: str) -> dict:
    read_only = set(read_only_actions_from(reference))
    return {
        "_source": {
            "generator": "tools/aws/regen_sqs_cloudtrail_events.py",
            "managementEvents": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/"
                                "logging-using-cloudtrail.html",
            "reference": provenance,
            "retrieved": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        },
        "managementEvents": sorted(MANAGEMENT_EVENTS),
        "readOnlyActions": sorted(name for name in MANAGEMENT_EVENTS if name in read_only),
    }


def render(document: dict) -> str:
    return json.dumps(document, indent=2) + "\n"


def validate(document: dict) -> list[str]:
    """Problems that make the vendored file unusable, rather than merely out of date."""
    problems: list[str] = []
    events = document.get("managementEvents")
    if events != sorted(MANAGEMENT_EVENTS):
        problems.append("managementEvents is not the guide's list, sorted")
        events = sorted(MANAGEMENT_EVENTS)
    read_only = document.get("readOnlyActions")
    if not isinstance(read_only, list):
        return problems + ["readOnlyActions is missing"]
    if read_only != sorted(set(read_only)):
        problems.append("readOnlyActions is not sorted or lists an action twice")
    for action in read_only:
        if action not in events:
            problems.append(f"readOnlyActions names {action!r}, which is not a management event")
    for action, expected in READ_ONLY_ANCHORS.items():
        if (action in read_only) != expected:
            problems.append(f"{action!r} should {'' if expected else 'not '}be read-only")
    return problems


def verify_against(document: dict, reference: dict) -> list[str]:
    """What the vendored file claims and the reference does not say."""
    published = {action.get("Name") for action in reference.get("Actions", [])}
    problems = [f"{name!r} is not an SQS action AWS publishes" for name in MANAGEMENT_EVENTS
                if name not in published]
    expected = build(reference, "")["readOnlyActions"]
    if document.get("readOnlyActions") != expected:
        problems.append(f"readOnlyActions is {document.get('readOnlyActions')}, the reference gives {expected}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="offline: exit 1 when the vendored file is unusable")
    parser.add_argument("--verify", action="store_true", help="online: exit 1 when the vendored file is not AWS's")
    parser.add_argument("--source", type=Path, default=None, help="read the service reference from this file")
    parser.add_argument("--output", type=Path, default=OUTPUT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.check or args.verify:
        document = json.loads(args.output.read_text(encoding="utf-8"))
        problems = validate(document)
        if args.verify and not problems:
            try:
                reference, _ = fetch_reference(args.source)
            except (OSError, ValueError) as e:
                # An unreachable reference, or an answer that is not JSON, verifies nothing.
                print(f"could not read the SQS service reference: {e}", file=sys.stderr)
                return 2
            problems = verify_against(document, reference)
        for problem in problems:
            print(f"{args.output.name}: {problem}", file=sys.stderr)
        return 1 if problems else 0

    reference, provenance = fetch_reference(args.source)
    document = build(reference, provenance)
    problems = validate(document)
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1
    args.output.write_text(render(document), encoding="utf-8")
    shown = args.output.relative_to(REPO_ROOT) if args.output.is_relative_to(REPO_ROOT) else args.output
    print(f"wrote {shown} from {provenance}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
