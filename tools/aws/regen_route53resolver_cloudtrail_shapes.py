#!/usr/bin/env python3
"""Regenerate src/main/resources/aws/route53resolver-cloudtrail-shapes.json from botocore's Route 53 Resolver
model.

CloudTrail records Route 53 Resolver's API calls, and `Route53ResolverCloudTrailEvents` writes each record's
`requestParameters` and `responseElements` from the call's JSON request and result. The file is
`request_shapes.build`'s, as SQS's (`regen_sqs_cloudtrail_shapes.py`): each operation's input shape, its
result shape, every shape they reach with its type and the `sensitive` flag.

"All Route 53 actions are logged by CloudTrail"
(https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/logging-using-cloudtrail.html), Resolver's among
them, but only the calls Floci serves are recorded, so only those operations' shapes are vendored
(`OPERATIONS`).

Resolver's model is a JSON one, so two member traits beside the shape a member names say nothing of how a
record names or types it: `idempotencyToken` and `box`, which only marks a member that may be left out. Any
other stops the generation.

The model is botocore's `route53resolver/2018-04-01/` (Apache-2.0, https://github.com/boto/botocore),
located, in order, at `--botocore-data`, the `local/aws/botocore` checkout, then the installed `botocore`
package, which `requirements.txt` pins so CI regenerates the same bytes.

Run from anywhere in the repo:
    python3 tools/aws/regen_route53resolver_cloudtrail_shapes.py            # rewrite the vendored file in place
    python3 tools/aws/regen_route53resolver_cloudtrail_shapes.py --check    # exit 1 when the vendored file is stale
"""
from __future__ import annotations

import sys
from pathlib import Path

import request_shapes
from request_shapes import REPO_ROOT

OUTPUT = REPO_ROOT / "src/main/resources/aws/route53resolver-cloudtrail-shapes.json"
MODEL = Path("route53resolver/2018-04-01")

# The Route 53 Resolver calls Floci serves, whose shapes are vendored.
OPERATIONS = (
    "AssociateResolverRule", "CreateFirewallDomainList", "CreateResolverEndpoint", "CreateResolverRule",
    "DeleteFirewallDomainList", "DeleteResolverEndpoint", "DeleteResolverRule", "DisassociateResolverRule",
    "GetFirewallDomainList", "GetResolverDnssecConfig", "GetResolverEndpoint", "GetResolverRule",
    "GetResolverRuleAssociation", "ListFirewallDomainLists", "ListResolverDnssecConfigs",
    "ListResolverEndpointIpAddresses", "ListResolverEndpoints", "ListResolverRuleAssociations",
    "ListResolverRules", "ListTagsForResource", "TagResource", "UntagResource", "UpdateResolverDnssecConfig",
    "UpdateResolverEndpoint", "UpdateResolverRule",
)

MEMBER_TRAITS = {"shape", "documentation", "idempotencyToken", "box"}
readable = request_shapes.record_check(MEMBER_TRAITS)


def main(argv: list[str] | None = None) -> int:
    return request_shapes.main(argv, script=__file__, model=MODEL, output=OUTPUT, description=__doc__,
                               results=True, sensitive=True, check=readable, subset=OPERATIONS)


if __name__ == "__main__":
    sys.exit(main())
