# CloudTrail

**Protocol:** JSON 1.1 (`X-Amz-Target: com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.*`)
**Endpoint:** `POST http://localhost:4566/`

Floci emulates a CloudTrail trail's full life cycle and emits S3 data and management events, IAM and STS API calls
and selected Secrets Manager management writes to the trail's destination bucket as gzipped JSON log files at the
AWS-shaped key path:

```
${prefix}AWSLogs/${accountId}/CloudTrail/${region}/yyyy/MM/dd/${accountId}_CloudTrail_${region}_${YYYYMMDDTHHMMZ}_${rand12}.json.gz
```

## Supported Actions

<!-- floci:actions:start -->
| Action | Description |
| --- | --- |
| `CreateTrail` | Creates a trail, optionally tagged via `TagsList`, and returns its ARN |
| `DescribeTrails` | Returns the settings for one or more trails |
| `DeleteTrail` | Deletes a trail |
| `UpdateTrail` | Updates the settings of an existing trail |
| `PutEventSelectors` | Configures the event selectors for a trail |
| `GetEventSelectors` | - |
| `StartLogging` | Starts logging for a trail |
| `StopLogging` | Stops logging for a trail |
| `GetTrailStatus` | Returns the logging status of a trail |
| `LookupEvents` | - |
| `ListTrails` | - |
| `AddTags` | Adds or overwrites tags on a trail, identified by ARN |
| `RemoveTags` | Removes the given tag keys from a trail, identified by ARN |
| `ListTags` | Returns the tags for one or more trails, identified by ARN |
<!-- floci:actions:end -->

Selector matching honors `ReadWriteType` (`All`, `ReadOnly`, `WriteOnly`)
and `AWS::S3::Object` data resource ARNs in any of these forms:

- `arn:aws:s3:::` — every bucket
- `arn:aws:s3:::bucket/` — every key in the bucket
- `arn:aws:s3:::bucket/prefix` — keys with the given prefix
- `arn:aws:s3:::bucket/prefix/key` — exact key match

## Encryption and CloudWatch Logs settings

`CreateTrail` and `UpdateTrail` record `KmsKeyId`, `CloudWatchLogsLogGroupArn` and `CloudWatchLogsRoleArn`, and `DescribeTrails` returns them, so a Terraform `aws_cloudtrail` with encryption or log delivery reads back what it declared. `UpdateTrail` with an empty value clears one, as on AWS. A log group without a role is refused with `InvalidCloudWatchLogsRoleArnException`, and a role without a log group with `InvalidCloudWatchLogsLogGroupArnException`. The settings are recorded only: log files are not encrypted, events are not delivered to the log group, and `KmsKeyId` is stored as sent (an alias is not resolved to the key ARN, and an unknown key is not refused).

## S3 Coverage

S3 requests are recorded under the event names and categories the S3 User Guide gives them
([Amazon S3 CloudTrail events](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html)),
which are not always the API's: `PutBucketLifecycleConfiguration` is `PutBucketLifecycle`,
`PutObjectLockConfiguration` is `PutBucketObjectLockConfiguration`, `PutPublicAccessBlock` is
`PutBucketPublicAccessBlock`, and `PutObjectRetention` is `PutObjectLockRetention`. The other Object Lock calls are
named the same way, as AWS's sample events and EventBridge schema for S3's CloudTrail events name them:
`GetObjectLockRetention`, `PutObjectLockLegalHold`, `GetObjectLockLegalHold`.

- **Data events**, matched by data event selectors: the object-level operations (`PutObject`, `GetObject`,
  `HeadObject`, `DeleteObject`, `CopyObject`, the object ACL, tagging, Object Lock, attributes and annotation
  operations, `CreateMultipartUpload`, `UploadPart`, `UploadPartCopy`, `CompleteMultipartUpload`,
  `AbortMultipartUpload`, `ListParts`, `RestoreObject`, `SelectObjectContent`), `ListObjects`, `ListObjectVersions`,
  `HeadBucket`, and `DeleteObjects`, followed by a `DeleteObject` for each object it deleted, as the guide says
  "the event record for an Amazon S3 DeleteObjects data event includes both the DeleteObjects event and a
  DeleteObject event for each object deleted". An Object Lock call carries the retention and legal hold it read or
  left in `additionalEventData.objectRetentionInfo`: `retentionInfo` (`retainUntilMode`, `retainUntilTime`,
  `lastModifiedTime`, in epoch milliseconds) for a retention call, `legalHoldInfo` (`isUnderLegalHold`,
  `lastModifiedTime`) for a legal hold call and for a retention a call sets on an object under one.
- **Management events**, matched by management event selectors: `ListBuckets`, `CreateBucket`, `DeleteBucket` and
  the bucket configuration operations the guide lists (versioning, lifecycle, Object Lock, policy, tagging, ACL,
  CORS, encryption, public access block, ownership controls, logging, notification, replication, website, request
  payment, accelerate, and the analytics, inventory, metrics and Intelligent-Tiering configurations).
  `requestParameters` carries `bucketName`, `Host`, the request's query parameters (a sub-resource with an empty
  value, `"versioning": ""`), an XML configuration body as the guide's `PutBucketAcl` record writes one
  (`"VersioningConfiguration": {"Status": "Suspended", "xmlns": "..."}`, booleans and numbers such as `Days` typed),
  and a bucket policy as its document under `bucketPolicy`. The record carries the bucket in `resources` (except
  for `CreateBucket`) and `additionalEventData`, and `responseElements` is `null`.

A request the guide lists no event for, such as `ListMultipartUploads`, is not recorded. Both success and error paths
emit; an error populates `errorCode` and `errorMessage` (`NoSuchKey`, `NoSuchBucketPolicy`, etc.), and a failure
whose response carries no error code, such as a failed `HEAD`, is not recorded.

If `floci.services.iam.enforcement-enabled` is set, IAM-deny responses also
emit records with `errorCode: "AccessDenied"`, named after the operation that
was refused, and an `errorMessage` in the format S3's
[access denied messages](https://docs.aws.amazon.com/AmazonS3/latest/userguide/troubleshoot-403-errors.html)
take, which "is also available in AWS CloudTrail logs" (`User: <caller> is not authorized to perform: <action>
on resource: "<resource>" because no identity-based policy allows the <action> action`). A request refused for a permission it needs besides its own, such as
`s3:PutObjectTagging` for an upload that sets tags, is recorded as the
operation. A browser `POST` upload, whose credential is in its form fields, is
recorded as `PostObject` when IAM refuses it.

## IAM Coverage

Every IAM API call is recorded as a management event, as CloudTrail
["logs all authenticated API requests to IAM"](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html):
one IAM ran, one IAM answered with an error, and, with `floci.services.iam.enforcement-enabled`, one IAM enforcement
refused.

- `eventSource` is `iam.amazonaws.com` and `awsRegion` the Region IAM signs for in the request's partition
  (`us-east-1` in `aws`).
- `readOnly` is `true` for the actions AWS's service reference
  ([`iam.json`](https://servicereference.us-east-1.amazonaws.com/v1/iam/iam.json)) gives the Read or List access
  level: those named `Get*`, `List*`, `Generate*` and `Simulate*`.
- `requestParameters` holds the request's members, named with a lower first letter (`userName`, `policyArn`,
  `tags: [{"key": ..., "value": ...}]`), numbers and booleans typed as the IAM model types them. Passwords are left out,
  and a request whose only members are passwords (`ChangePassword`) has `"requestParameters": null`.
- `responseElements` is `null` for a failed call and for a read-only one, as CloudTrail
  "redacts the responseElements information" of a read-only event. Otherwise it holds the call's result
  (`{"accessKey": {...}}` for `CreateAccessKey`), with booleans and counts typed, timestamps written as CloudTrail
  writes them (`Oct 29, 2024 2:43:20 PM`), and without secrets (`secretAccessKey`, a service-specific credential's
  password, a virtual MFA device's seed).
- An error IAM models is recorded under its error shape's name: `NoSuchEntity` as `NoSuchEntityException`,
  `DeleteConflict` as `DeleteConflictException`, with IAM's message. A call IAM enforcement refuses is recorded as
  `errorCode: "AccessDenied"` and `"requestParameters": null`, its message in the
  [access denied format](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html)
  (`User: <caller> is not authorized to perform: <action> on resource: <resource> because ...`).
- `sourceIPAddress` is the address the request came from and `userAgent` its `User-Agent`; `requestID` is the one
  IAM answered with.

## STS Coverage

Every STS API call is recorded as a management event, as CloudTrail
["logs all authenticated API requests to IAM and AWS STS API operations"](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html):
one STS ran, one STS refused, and, with `floci.services.iam.enforcement-enabled`, one IAM enforcement refused.

- `eventSource` is `sts.amazonaws.com` and `awsRegion` the Region the request was signed for.
- `readOnly` and `responseElements` follow the
  [IAM User Guide's table](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html#cloudtrail-integration_signin-tempcreds):
  `AssumeRole`, `AssumeRoleWithSAML` and `AssumeRoleWithWebIdentity` are read-only and carry the call's result;
  `AssumeRoot`, `GetFederationToken` and `GetSessionToken` are not read-only and carry it too. `GetWebIdentityToken`
  is not read-only and carries no result, the token being a bearer credential. Any other call (`GetCallerIdentity`,
  `GetAccessKeyInfo`, `DecodeAuthorizationMessage`) is read-only with `"responseElements": null`.
- `requestParameters` holds the request's members, named with a lower first letter and typed as the STS model types
  them (`"durationSeconds": 900`, `tags: [{"key": ..., "value": ...}]`). The MFA code (`tokenCode`), the SAML assertion,
  the web identity token and a trade-in token are left out.
- `responseElements` never carries `secretAccessKey`; a credential's `expiration` is written as the guide's records
  write it (`Feb 12, 2025, 11:16:48 PM`).
- `AssumeRole`, `AssumeRoleWithSAML` and `AssumeRoleWithWebIdentity` carry the role in `resources`
  (`AWS::IAM::Role`), and `AssumeRoleWithSAML` the SAML provider too.
- `AssumeRoleWithSAML` and `AssumeRoleWithWebIdentity` name their caller as a `SAMLUser` or a `WebIdentityUser`. They
  are recorded once STS accepted the assertion or the token; the guide says some non-authenticated STS requests "might
  not be logged".
- A refused call (`AccessDenied`) is recorded with its message, `"requestParameters": null` and no `resources`; any
  other error keeps the request's members.

## Management Write Coverage

Successful Secrets Manager `PutSecretValue` and `UpdateSecret` API calls produce management
records when a logging trail selects them. New trails include management events by default.
Basic selectors honor `IncludeManagementEvents`, `ReadWriteType` (against each event's `readOnly`), and source exclusions.
Advanced selectors evaluate `eventCategory`, `eventSource`, `eventName`, `readOnly`, `eventType`,
and `userIdentity.arn`; unsupported fields do not match these records.

Records have `eventCategory: Management` and `managementEvent: true`; the Secrets Manager writes have `readOnly: false`.
Sensitive secret values are omitted. Buffers and background S3 delivery retain the originating
account, including when different accounts use the same trail name. Multi-region trails cover
regions within their own partition.

These writes also reach EventBridge's default bus in the request's account and region. See
[Secrets Manager event delivery](secrets-manager.md#secret-write-events) for prerequisites,
the secret-specific event pattern, and the limits of this coverage.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `FLOCI_SERVICES_CLOUDTRAIL_ENABLED` | `true` | Enable or disable the service |
| `FLOCI_SERVICES_CLOUDTRAIL_FLUSH_INTERVAL_SECONDS` | `60` | How often the writer flushes buffered records into the destination bucket. Real CloudTrail delivers with ~5 minute latency; the local default is shorter for fast feedback loops. |

## Example

```bash
export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test

aws s3 mb s3://my-source
aws s3 mb s3://my-trail-logs

aws cloudtrail create-trail \
    --name my-trail \
    --s3-bucket-name my-trail-logs

aws cloudtrail put-event-selectors \
    --trail-name my-trail \
    --event-selectors '[{
        "ReadWriteType": "All",
        "IncludeManagementEvents": false,
        "DataResources": [{
            "Type": "AWS::S3::Object",
            "Values": ["arn:aws:s3:::my-source/"]
        }]
    }]'

aws cloudtrail start-logging --name my-trail

# Drive some traffic
echo hello | aws s3 cp - s3://my-source/greeting.txt
aws s3 cp s3://my-source/greeting.txt -

# After ~60s, log files appear
aws s3 ls s3://my-trail-logs/AWSLogs/ --recursive
```
