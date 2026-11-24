"""Tests for regen_backup_cloudtrail_shapes: the shapes it vendors are those of the calls the CloudTrail
catalog records for AWS Backup, no more and no fewer.

Run with: pytest tools/aws -q  (or: make aws-data-test)
"""
from __future__ import annotations

import regen_backup_cloudtrail_shapes as shapes
import regen_cloudtrail_events as events


def test_the_vendored_operations_are_the_recorded_management_events():
    assert sorted(shapes.OPERATIONS) == sorted(events.SERVICES["backup"].management_events)
