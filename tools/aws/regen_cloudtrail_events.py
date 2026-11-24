#!/usr/bin/env python3
"""Regenerate src/main/resources/aws/<service>-cloudtrail-events.json: which of a service's calls
CloudTrail records as management events, and which of them are read-only.

Which calls are management events is each service's guide's, which no machine-readable source
carries, so it stays in SERVICES below, as the guide lists them:

- SQS (https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/logging-using-cloudtrail.html):
  "Amazon SQS logs the following control plane operations to CloudTrail as management events".
  Every other SQS call (sending, receiving and deleting messages, and reading a queue's URL,
  attributes and tags) is a data event of the `AWS::SQS::Queue` resource type, which a trail logs
  only when an advanced event selector selects it.
- Secrets Manager (https://docs.aws.amazon.com/secretsmanager/latest/userguide/cloudtrail_log_entries.html):
  "AWS Secrets Manager writes entries to your AWS CloudTrail log for all Secrets Manager
  operations", followed by the entries its operations generate.
- KMS (https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html): "CloudTrail
  logs all AWS KMS operations", so every operation of botocore's KMS model.
- CloudWatch Logs (https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/logging_cw_api_calls_cwl.html):
  "CloudWatch Logs supports logging the following actions as events in CloudTrail log files", followed
  by the list. `PutLogEvents` is not in it.
- EC2 (https://docs.aws.amazon.com/AWSEC2/latest/APIReference/using-cloudtrail.html): every EC2 API call
  is a management event, but an EC2 record's members follow EC2's own schema rather than botocore's,
  so Floci records only the calls whose record a recent capture shows (Ec2CloudTrailEvents).
- EventBridge (https://docs.aws.amazon.com/eventbridge/latest/userguide/logging-using-cloudtrail.html):
  "All Amazon EventBridge API operations except PutEvents and PutPartnerEvents are control plane
  operations", so every other operation of botocore's EventBridge model (`events/2015-10-07/`).
- Lambda (https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html): "Lambda supports
  logging the following actions as management events in CloudTrail log files", followed by the list.
  A record names most of them with the API version they are served under (`CreateFunction20150331`),
  which the file carries as `eventNames`: "the `eventName` might include date and version information,
  but it is still referring to the same public API action".

Which of them are read-only is the access level AWS's Service Reference gives each action, read as
`regen_iam_action_resources.py` reads IAM's: an action with none of the Write, Permissions
management or Tagging properties is one CloudTrail "considers ... read-only"
(https://servicereference.us-east-1.amazonaws.com/v1/<service>/<service>.json). That endpoint is
live, so a fresh generation can differ from a vendored file only when AWS changes an access level.
A service guide can also show calls read-only whose access level is Write: KMS's cryptographic
operations, which its log entry examples record with `"readOnly": true`. SERVICES lists those.


- `--check` is offline and structural: each file lists exactly its service's management events,
  sorted, its read-only actions are among them, and the anchors SERVICES gives (a read that is
  read-only, a write that is not) hold.
- `--verify` needs the network: every management event is an action the reference publishes, and
  the read-only list is the one the reference gives.

Run from anywhere in the repo:
    python3 tools/aws/regen_cloudtrail_events.py           # rewrite every vendored file in place
    python3 tools/aws/regen_cloudtrail_events.py --check   # offline: shape of the vendored files
    python3 tools/aws/regen_cloudtrail_events.py --verify  # online: the access levels are AWS's (2: unreachable)
    python3 tools/aws/regen_cloudtrail_events.py --service sqs --source <file>  # one service, from a saved copy
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from regen_iam_action_resources import read_only_actions_from

REPO_ROOT = Path(__file__).resolve().parents[2]
RESOURCES = REPO_ROOT / "src/main/resources/aws"
REFERENCE_URL = "https://servicereference.us-east-1.amazonaws.com/v1/{service}/{service}.json"
FETCH_TIMEOUT_SECONDS = 30


@dataclass(frozen=True)
class Service:
    """A service's guide, the calls it lists as management events, and the access levels to keep."""

    guide: str
    management_events: tuple[str, ...]
    # Read-only or not, whichever way the reference says, for a read and a write the file must carry.
    read_only_anchors: dict[str, bool]
    # Calls the guide shows read-only although the reference gives them a mutating access level.
    read_only_operations: tuple[str, ...] = ()
    # Calls the reference authorizes under other action names, rather than their own.
    reference_actions: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # The name a call's record gives it, where it is not the call's own.
    event_names: dict[str, str] = field(default_factory=dict)


SERVICES: dict[str, Service] = {
    "sqs": Service(
        guide="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/logging-using-cloudtrail.html",
        management_events=(
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
        ),
        read_only_anchors={"ListMessageMoveTasks": True, "DeleteQueue": False},
    ),
    "ec2": Service(
        guide="https://docs.aws.amazon.com/AWSEC2/latest/APIReference/using-cloudtrail.html",
        management_events=(
            "AttachVolume", "AuthorizeSecurityGroupEgress", "AuthorizeSecurityGroupIngress", "CopyImage",
            "CopySnapshot", "CreateFlowLogs", "CreateImage", "CreateKeyPair", "CreateNetworkAcl",
            "CreateNetworkAclEntry", "CreateSecurityGroup", "CreateSnapshot", "CreateVolume", "DeleteFlowLogs",
            "DeleteNetworkAcl", "DeleteNetworkAclEntry", "DeleteSecurityGroup", "DeleteSnapshot",
            "DeleteVolume", "DeregisterImage", "DetachVolume", "GetPasswordData", "ImportKeyPair",
            "ModifyImageAttribute", "ModifyInstanceAttribute", "ModifySecurityGroupRules",
            "ModifySnapshotAttribute", "ReplaceNetworkAclEntry", "RevokeSecurityGroupEgress",
            "RevokeSecurityGroupIngress", "RunInstances", "StartInstances", "StopInstances",
            "TerminateInstances",
        ),
        read_only_anchors={"GetPasswordData": True, "TerminateInstances": False},
    ),
    "events": Service(
        guide="https://docs.aws.amazon.com/eventbridge/latest/userguide/logging-using-cloudtrail.html",
        # Every operation of botocore's EventBridge model but PutEvents and PutPartnerEvents, the data events.
        management_events=(
            "ActivateEventSource", "CancelReplay", "CreateApiDestination", "CreateArchive", "CreateConnection",
            "CreateEndpoint", "CreateEventBus", "CreatePartnerEventSource", "DeactivateEventSource",
            "DeauthorizeConnection", "DeleteApiDestination", "DeleteArchive", "DeleteConnection", "DeleteEndpoint",
            "DeleteEventBus", "DeletePartnerEventSource", "DeleteRule", "DescribeApiDestination", "DescribeArchive",
            "DescribeConnection", "DescribeEndpoint", "DescribeEventBus", "DescribeEventSource",
            "DescribePartnerEventSource", "DescribeReplay", "DescribeRule", "DisableRule", "EnableRule",
            "ListApiDestinations", "ListArchives", "ListConnections", "ListEndpoints", "ListEventBuses",
            "ListEventSources", "ListPartnerEventSourceAccounts", "ListPartnerEventSources", "ListReplays",
            "ListRuleNamesByTarget", "ListRules", "ListTagsForResource", "ListTargetsByRule", "PutPermission",
            "PutRule", "PutTargets", "RemovePermission", "RemoveTargets", "StartReplay", "TagResource",
            "TestEventPattern", "UntagResource", "UpdateApiDestination", "UpdateArchive", "UpdateConnection",
            "UpdateEndpoint", "UpdateEventBus",
        ),
        read_only_anchors={"DescribeRule": True, "ListRules": True, "DeleteRule": False},
    ),
    "kms": Service(
        guide="https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html",
        management_events=(
            "CancelKeyDeletion", "ConnectCustomKeyStore", "CreateAlias", "CreateCustomKeyStore", "CreateGrant",
            "CreateKey", "Decrypt", "DeleteAlias", "DeleteCustomKeyStore", "DeleteImportedKeyMaterial",
            "DeriveSharedSecret", "DescribeCustomKeyStores", "DescribeKey", "DisableKey", "DisableKeyRotation",
            "DisconnectCustomKeyStore", "EnableKey", "EnableKeyRotation", "Encrypt", "GenerateDataKey",
            "GenerateDataKeyPair", "GenerateDataKeyPairWithoutPlaintext", "GenerateDataKeyWithoutPlaintext",
            "GenerateMac", "GenerateRandom", "GetKeyLastUsage", "GetKeyPolicy", "GetKeyRotationStatus",
            "GetParametersForImport", "GetPublicKey", "ImportKeyMaterial", "ListAliases", "ListGrants",
            "ListKeyPolicies", "ListKeyRotations", "ListKeys", "ListResourceTags", "ListRetirableGrants",
            "PutKeyPolicy", "ReEncrypt", "ReplicateKey", "RetireGrant", "RevokeGrant", "RotateKeyOnDemand",
            "ScheduleKeyDeletion", "Sign", "TagResource", "UntagResource", "UpdateAlias", "UpdateCustomKeyStore",
            "UpdateKeyDescription", "UpdatePrimaryRegion", "Verify", "VerifyMac",
        ),
        read_only_anchors={"Decrypt": True, "ListAliases": True, "ScheduleKeyDeletion": False},
        # The cryptographic operations (https://docs.aws.amazon.com/kms/latest/developerguide/
        # kms-cryptography.html#cryptographic-operations), which the log entry examples record
        # read-only (ct-decrypt.html, ct-encrypt.html, ct-reencrypt.html, ct-sign.html, ...).
        read_only_operations=(
            "Decrypt", "DeriveSharedSecret", "Encrypt", "GenerateDataKey", "GenerateDataKeyPair",
            "GenerateDataKeyPairWithoutPlaintext", "GenerateDataKeyWithoutPlaintext", "GenerateMac",
            "GenerateRandom", "ReEncrypt", "Sign", "Verify", "VerifyMac",
        ),
        # Its required permissions are "kms:ReEncryptFrom permission on the source KMS key" and
        # "kms:ReEncryptTo permission on the destination KMS key"
        # (https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html).
        reference_actions={"ReEncrypt": ("ReEncryptFrom", "ReEncryptTo")},
    ),
    "lambda": Service(
        guide="https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html",
        # The guide's list, but GetLayerVersionPolicy, whose event name no record shows: the guide names it
        # without a version, as it does calls whose records carry one (GetFunction, AddLayerVersionPermission).
        # With the calls the guide leaves out that records show as management events: one month of real logs
        # (July 2025) counts GetAccountSettings20160819, GetEventSourceMapping20150331,
        # GetFunctionCodeSigningConfig, GetFunctionEventInvokeConfig, ListAliases20150331, ListLayers20181031,
        # ListTags20170331 and ListVersionsByFunction20150331, as an export of 849 management events
        # (published July 2025) and a timeline of September 2026 (GetAccountSettings20160819) also name them.
        management_events=(
            "AddLayerVersionPermission", "AddPermission", "CreateAlias", "CreateEventSourceMapping",
            "CreateFunction", "CreateFunctionUrlConfig", "DeleteAlias", "DeleteCodeSigningConfig",
            "DeleteEventSourceMapping", "DeleteFunction", "DeleteFunctionConcurrency",
            "DeleteFunctionUrlConfig", "DeleteProvisionedConcurrencyConfig", "GetAccountSettings", "GetAlias",
            "GetEventSourceMapping", "GetFunction", "GetFunctionCodeSigningConfig", "GetFunctionConfiguration",
            "GetFunctionEventInvokeConfig", "GetFunctionUrlConfig", "GetPolicy", "ListAliases",
            "ListEventSourceMappings", "ListFunctionUrlConfigs", "ListFunctions", "ListLayers", "ListTags",
            "ListVersionsByFunction", "PublishLayerVersion", "PublishVersion", "PutFunctionCodeSigningConfig",
            "PutFunctionConcurrency", "PutFunctionEventInvokeConfig", "PutProvisionedConcurrencyConfig",
            "PutRuntimeManagementConfig", "RemovePermission", "TagResource", "UntagResource", "UpdateAlias",
            "UpdateCodeSigningConfig", "UpdateEventSourceMapping", "UpdateFunctionCode",
            "UpdateFunctionConfiguration", "UpdateFunctionEventInvokeConfig", "UpdateFunctionUrlConfig",
        ),
        read_only_anchors={"GetFunction": True, "ListFunctions": True, "DeleteFunction": False},
        # The guide's event names, and where a record shows otherwise, the record's: GetFunction,
        # GetFunctionConfiguration and ListFunctions (2026 and July 2025), ListEventSourceMappings (July 2025),
        # and AddLayerVersionPermission (2026), which the guide names without a version. GetPolicy is logged
        # both as GetPolicy20150331v2 and GetPolicy20150331 (July 2025); the first is the one its 2020 records
        # show for an API call. The
        # calls the guide names without one and no record contradicts keep their own name, as the
        # records of CreateFunctionUrlConfig (2026), GetFunctionCodeSigningConfig (2023) and
        # GetFunctionEventInvokeConfig (2020) keep theirs.
        event_names={
            "AddLayerVersionPermission": "AddLayerVersionPermission20181031",
            "AddPermission": "AddPermission20150331v2",
            "CreateAlias": "CreateAlias20150331",
            "CreateEventSourceMapping": "CreateEventSourceMapping20150331",
            "CreateFunction": "CreateFunction20150331",
            "DeleteAlias": "DeleteAlias20150331",
            "DeleteEventSourceMapping": "DeleteEventSourceMapping20150331",
            "DeleteFunction": "DeleteFunction20150331",
            "DeleteFunctionConcurrency": "DeleteFunctionConcurrency20171031",
            "GetAccountSettings": "GetAccountSettings20160819",
            "GetAlias": "GetAlias20150331",
            "GetEventSourceMapping": "GetEventSourceMapping20150331",
            "GetFunction": "GetFunction20150331v2",
            "GetFunctionConfiguration": "GetFunctionConfiguration20150331v2",
            "GetPolicy": "GetPolicy20150331v2",
            "ListAliases": "ListAliases20150331",
            "ListEventSourceMappings": "ListEventSourceMappings20150331",
            "ListFunctions": "ListFunctions20150331",
            "ListLayers": "ListLayers20181031",
            "ListTags": "ListTags20170331",
            "ListVersionsByFunction": "ListVersionsByFunction20150331",
            "PublishLayerVersion": "PublishLayerVersion20181031",
            "PublishVersion": "PublishVersion20150331",
            "PutFunctionConcurrency": "PutFunctionConcurrency20171031",
            "RemovePermission": "RemovePermission20150331v2",
            "TagResource": "TagResource20170331v2",
            "UntagResource": "UntagResource20170331v2",
            "UpdateAlias": "UpdateAlias20150331",
            "UpdateEventSourceMapping": "UpdateEventSourceMapping20150331",
            "UpdateFunctionCode": "UpdateFunctionCode20150331v2",
            "UpdateFunctionConfiguration": "UpdateFunctionConfiguration20150331v2",
        },
    ),
    "logs": Service(
        guide="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/logging_cw_api_calls_cwl.html",
        management_events=(
            "AssociateKmsKey", "CancelExportTask", "CreateDelivery", "CreateExportTask", "CreateLogAnomalyDetector",
            "CreateLogGroup", "CreateLogStream", "DeleteAccountPolicy", "DeleteDataProtectionPolicy",
            "DeleteDelivery", "DeleteDeliveryDestination", "DeleteDeliveryDestinationPolicy", "DeleteDeliverySource",
            "DeleteDestination", "DeleteIndexPolicy", "DeleteIntegration", "DeleteLogAnomalyDetector",
            "DeleteLogGroup", "DeleteLogStream", "DeleteMetricFilter", "DeleteQueryDefinition",
            "DeleteResourcePolicy", "DeleteRetentionPolicy", "DeleteSubscriptionFilter", "DeleteTransformer",
            "DescribeAccountPolicies", "DescribeConfigurationTemplates", "DescribeDeliveries",
            "DescribeDeliveryDestinations", "DescribeDeliverySources", "DescribeDestinations", "DescribeExportTasks",
            "DescribeFieldIndexes", "DescribeIndexPolicies", "DescribeLogGroups", "DescribeLogStreams",
            "DescribeMetricFilters", "DescribeQueries", "DescribeQueryDefinitions", "DescribeResourcePolicies",
            "DescribeSubscriptionFilters", "DisassociateKmsKey", "FilterLogEvents", "GetDataProtectionPolicy",
            "GetDelivery", "GetDeliveryDestination", "GetDeliveryDestinationPolicy", "GetDeliverySource",
            "GetIntegration", "GetLogAnomalyDetector", "GetLogEvents", "GetLogGroupFields", "GetLogRecord",
            "GetQueryResults", "GetTransformer", "ListAnomalies", "ListIntegrations", "ListLogAnomalyDetectors",
            "ListLogGroups", "ListLogGroupsForQuery", "ListTagsForResource", "ListTagsLogGroup", "PutAccountPolicy",
            "PutDataProtectionPolicy", "PutDeliveryDestination", "PutDeliveryDestinationPolicy", "PutDeliverySource",
            "PutDestination", "PutDestinationPolicy", "PutIndexPolicy", "PutIntegration", "PutMetricFilter",
            "PutQueryDefinition", "PutResourcePolicy", "PutRetentionPolicy", "PutSubscriptionFilter",
            "PutTransformer", "StartLiveTail", "StartQuery", "StopQuery", "TagResource", "TestMetricFilter",
            "TestTransformer", "UntagResource", "UpdateAnomaly", "UpdateDeliveryConfiguration",
            "UpdateLogAnomalyDetector",
        ),
        read_only_anchors={"DescribeLogGroups": True, "DeleteLogGroup": False},
    ),
    "secretsmanager": Service(
        guide="https://docs.aws.amazon.com/secretsmanager/latest/userguide/cloudtrail_log_entries.html",
        management_events=(
            "BatchGetSecretValue",
            "CancelRotateSecret",
            "CreateSecret",
            "DeleteResourcePolicy",
            "DeleteSecret",
            "DescribeSecret",
            "GetRandomPassword",
            "GetResourcePolicy",
            "GetSecretValue",
            "ListSecretVersionIds",
            "ListSecrets",
            "PutResourcePolicy",
            "PutSecretValue",
            "RemoveRegionsFromReplication",
            "ReplicateSecretToRegions",
            "RestoreSecret",
            "RotateSecret",
            "StopReplicationToReplica",
            "TagResource",
            "UntagResource",
            "UpdateSecret",
            "UpdateSecretVersionStage",
            "ValidateResourcePolicy",
        ),
        read_only_anchors={"GetSecretValue": True, "DeleteSecret": False},
    ),
}


def output_for(service: str) -> Path:
    return RESOURCES / f"{service}-cloudtrail-events.json"


def fetch_reference(service: str, source: Path | None) -> tuple[dict, str]:
    """AWS's service reference for `service` and a provenance label for where it came from."""
    if source is not None:
        return json.loads(source.read_text(encoding="utf-8")), f"--source {source}"
    url = REFERENCE_URL.format(service=service)
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
        payload = response.read().decode("utf-8")
    return json.loads(payload), url


def build(service: str, reference: dict, provenance: str) -> dict:
    spec = SERVICES[service]
    read_only = set(read_only_actions_from(reference)) | set(spec.read_only_operations)
    return {
        "_source": {
            "generator": "tools/aws/regen_cloudtrail_events.py",
            "managementEvents": spec.guide,
            "reference": provenance,
            "retrieved": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        },
        "managementEvents": sorted(spec.management_events),
        "readOnlyActions": sorted(name for name in spec.management_events if name in read_only),
        **({"eventNames": dict(sorted(spec.event_names.items()))} if spec.event_names else {}),
    }


def render(document: dict) -> str:
    return json.dumps(document, indent=2) + "\n"


def validate(service: str, document: dict) -> list[str]:
    """Problems that make the vendored file unusable, rather than merely out of date."""
    spec = SERVICES[service]
    problems: list[str] = []
    events = document.get("managementEvents")
    if events != sorted(spec.management_events):
        problems.append("managementEvents is not the guide's list, sorted")
        events = sorted(spec.management_events)
    read_only = document.get("readOnlyActions")
    if not isinstance(read_only, list):
        return problems + ["readOnlyActions is missing"]
    if read_only != sorted(set(read_only)):
        problems.append("readOnlyActions is not sorted or lists an action twice")
    for action in read_only:
        if action not in events:
            problems.append(f"readOnlyActions names {action!r}, which is not a management event")
    for action, expected in spec.read_only_anchors.items():
        if (action in read_only) != expected:
            problems.append(f"{action!r} should {'' if expected else 'not '}be read-only")
    names = document.get("eventNames", {})
    if names != dict(sorted(spec.event_names.items())):
        problems.append("eventNames is not SERVICES' list, sorted")
    for action in names:
        if action not in events:
            problems.append(f"eventNames names {action!r}, which is not a management event")
    return problems


def verify_against(service: str, document: dict, reference: dict) -> list[str]:
    """What the vendored file claims and the reference does not say."""
    published = {action.get("Name") for action in reference.get("Actions", [])}
    spec = SERVICES[service]
    problems = [f"{name!r} is not a {service} action AWS publishes" for name in spec.management_events
                if not any(action in published for action in spec.reference_actions.get(name, (name,)))]
    expected = build(service, reference, "")["readOnlyActions"]
    if document.get("readOnlyActions") != expected:
        problems.append(f"readOnlyActions is {document.get('readOnlyActions')}, the reference gives {expected}")
    return problems


def check(service: str, output: Path, online: bool, source: Path | None) -> int:
    document = json.loads(output.read_text(encoding="utf-8"))
    problems = validate(service, document)
    if online and not problems:
        try:
            reference, _ = fetch_reference(service, source)
        except (OSError, ValueError) as e:
            # An unreachable reference, or an answer that is not JSON, verifies nothing.
            print(f"could not read the {service} service reference: {e}", file=sys.stderr)
            return 2
        problems = verify_against(service, document, reference)
    for problem in problems:
        print(f"{output.name}: {problem}", file=sys.stderr)
    return 1 if problems else 0


def regenerate(service: str, output: Path, source: Path | None) -> int:
    reference, provenance = fetch_reference(service, source)
    document = build(service, reference, provenance)
    problems = validate(service, document)
    if problems:
        for problem in problems:
            print(f"error: {service}: {problem}", file=sys.stderr)
        return 1
    output.write_text(render(document), encoding="utf-8")
    shown = output.relative_to(REPO_ROOT) if output.is_relative_to(REPO_ROOT) else output
    print(f"wrote {shown} from {provenance}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="offline: exit 1 when a vendored file is unusable")
    parser.add_argument("--verify", action="store_true", help="online: exit 1 when a vendored file is not AWS's")
    parser.add_argument("--service", choices=sorted(SERVICES), default=None, help="only this service")
    parser.add_argument("--source", type=Path, default=None,
                        help="read the service reference from this file (with --service)")
    parser.add_argument("--output", type=Path, default=None, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if (args.source is not None or args.output is not None) and args.service is None:
        parser.error("--source and --output need --service")

    status = 0
    for service in [args.service] if args.service else sorted(SERVICES):
        output = args.output if args.output is not None else output_for(service)
        if args.check or args.verify:
            result = check(service, output, args.verify, args.source)
        else:
            result = regenerate(service, output, args.source)
        # An unreachable reference (2) outranks a mismatch (1): nothing was verified.
        status = max(status, result)
    return status


if __name__ == "__main__":
    sys.exit(main())
