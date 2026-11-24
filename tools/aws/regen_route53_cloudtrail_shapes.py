#!/usr/bin/env python3
"""Regenerate src/main/resources/aws/route53-cloudtrail-shapes.json from botocore's Route 53 model.

CloudTrail records Route 53's API calls, and `Route53CloudTrailEvents` writes each record's
`requestParameters` and `responseElements` from the call's request and answer. The file is
`request_shapes.build`'s, as Lambda's (`regen_lambda_cloudtrail_shapes.py`): each operation's input shape,
its result shape, every shape they reach with its type and the `sensitive` flag.

"All Route 53 actions are logged by CloudTrail"
(https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/logging-using-cloudtrail.html), but only the
calls Floci serves are recorded, so only those operations' shapes are vendored (`OPERATIONS`).

Route 53's model is a REST-XML one. The members it carries in its path and its query are kept with the
structure's `locations`, as Lambda's are, and so is the `Location` header an answer carries, which a record
writes as `"location"`. Every other member travels in the XML body as an element named after it, which is
why a member's `locationName` is accepted only beside a `location`: a body member renamed on the wire would
be misread. Beside those, `idempotencyToken` says nothing of how a record types or names a member. Any other
trait stops the generation.

The model is botocore's `route53/2013-04-01/` (Apache-2.0, https://github.com/boto/botocore), located, in
order, at `--botocore-data`, the `local/aws/botocore` checkout, then the installed `botocore` package, which
`requirements.txt` pins so CI regenerates the same bytes.

Run from anywhere in the repo:
    python3 tools/aws/regen_route53_cloudtrail_shapes.py            # rewrite the vendored file in place
    python3 tools/aws/regen_route53_cloudtrail_shapes.py --check    # exit 1 when the vendored file is stale
"""
from __future__ import annotations

import sys
from pathlib import Path

import request_shapes
from request_shapes import REPO_ROOT

OUTPUT = REPO_ROOT / "src/main/resources/aws/route53-cloudtrail-shapes.json"
MODEL = Path("route53/2013-04-01")

# The Route 53 calls Floci serves, whose shapes are vendored.
OPERATIONS = (
    "AssociateVPCWithHostedZone", "ChangeResourceRecordSets", "ChangeTagsForResource", "CreateHealthCheck",
    "CreateHostedZone", "CreateReusableDelegationSet", "CreateVPCAssociationAuthorization", "DeleteHealthCheck",
    "DeleteHostedZone", "DeleteReusableDelegationSet", "DeleteVPCAssociationAuthorization",
    "DisassociateVPCFromHostedZone", "GetAccountLimit", "GetChange", "GetDNSSEC", "GetHealthCheck",
    "GetHealthCheckStatus", "GetHostedZone", "GetHostedZoneCount", "GetHostedZoneLimit",
    "GetReusableDelegationSet", "ListHealthChecks", "ListHostedZones", "ListHostedZonesByName",
    "ListHostedZonesByVPC", "ListResourceRecordSets", "ListReusableDelegationSets", "ListTagsForResource",
    "ListVPCAssociationAuthorizations", "UpdateHealthCheck", "UpdateHostedZoneComment",
)

MEMBER_TRAITS = {"shape", "documentation", "location", "locationName", "idempotencyToken"}
_traits = request_shapes.record_check(MEMBER_TRAITS)


def readable(name: str, shape: dict) -> None:
    _traits(name, shape)
    if shape.get("flattened"):
        raise ValueError(f"{name} is flattened, which the record does not read")
    for member, spec in shape.get("members", {}).items():
        if "locationName" in spec and "location" not in spec:
            raise ValueError(f"{name}.{member} is renamed in the body, which the record would misname")


def main(argv: list[str] | None = None) -> int:
    return request_shapes.main(argv, script=__file__, model=MODEL, output=OUTPUT, description=__doc__,
                               results=True, sensitive=True, check=readable, subset=OPERATIONS, located=True)


if __name__ == "__main__":
    sys.exit(main())
