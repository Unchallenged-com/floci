# CloudTrail

**Protocol:** JSON 1.1 (`X-Amz-Target: com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.*`)
**Endpoint:** `POST http://localhost:4566/`

Floci emulates a CloudTrail trail's full life cycle and emits S3 data events, IAM API calls, SQS control plane calls,
Secrets Manager, KMS and CloudWatch Logs API calls and some EC2 calls to the trail's destination bucket as gzipped JSON log files at the
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
| `LookupEvents` | Returns the management events in the account's event history, newest first |
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

## Source address

`sourceIPAddress` is "the IP address that the request was made from"
([CloudTrail record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)):
the address of the connection Floci received the request on. An `X-Forwarded-For` header is not read on its own,
since any client can send one. Behind a reverse proxy, Quarkus's own proxy settings make the address it forwards
the source address, from the proxies they name only:

```bash
QUARKUS_HTTP_PROXY_PROXY_ADDRESS_FORWARDING=true
QUARKUS_HTTP_PROXY_ALLOW_X_FORWARDED=true
QUARKUS_HTTP_PROXY_TRUSTED_PROXIES=10.0.0.5   # the proxy's address or range
```

Quarkus takes the first address in `X-Forwarded-For`, so the proxy must set the header to the address its own
connection came from, replacing any the client sent (nginx's `proxy_set_header X-Forwarded-For $remote_addr`). A
proxy that appends to the client's header (nginx's `$proxy_add_x_forwarded_for`) leaves the client's choice first,
and that is what gets recorded.

With `floci.tls.enabled`, Floci's own TCP proxy relays every connection to Quarkus, so the source address is the
loopback address.

## Encryption and CloudWatch Logs settings

`CreateTrail` and `UpdateTrail` record `KmsKeyId`, `CloudWatchLogsLogGroupArn` and `CloudWatchLogsRoleArn`, and `DescribeTrails` returns them, so a Terraform `aws_cloudtrail` with encryption or log delivery reads back what it declared. `UpdateTrail` with an empty value clears one, as on AWS. A log group without a role is refused with `InvalidCloudWatchLogsRoleArnException`, and a role without a log group with `InvalidCloudWatchLogsLogGroupArnException`. The settings are recorded only: log files are not encrypted, events are not delivered to the log group, and `KmsKeyId` is stored as sent (an alias is not resolved to the key ARN, and an unknown key is not refused).

## S3 Hook Coverage

Floci emits a CloudTrail data event whenever any of these S3 ops runs
against a bucket matched by an active trail's selectors:

- `PutObject`, `GetObject`, `HeadObject`, `DeleteObject`, `ListObjects`,
  `GetObjectAcl`

Both success and `AwsException` paths emit; the latter populates
`errorCode` / `errorMessage` (`NoSuchKey`, `NoSuchBucketPolicy`, etc.).

If `floci.services.iam.enforcement-enabled` is set, IAM-deny responses also
emit records with `errorCode: "AccessDenied"`, named after the operation that
was refused. Besides the ops above, that covers the object ACL and tagging
operations, `PutObjectRetention`, `GetObjectAttributes`, and the `POST`
operations `CreateMultipartUpload`, `CompleteMultipartUpload`, `RestoreObject`
and `SelectObjectContent`. A `POST` is named from the request's
sub-resource, since `CreateMultipartUpload` and `CompleteMultipartUpload` are
both checked as `s3:PutObject` and `SelectObjectContent` as `s3:GetObject`. A request
refused for a permission it needs besides its own, such as
`s3:PutObjectTagging` for an upload that sets tags, is recorded as the
operation. A browser `POST` upload, whose credential is in its form fields, is
recorded as `PostObject` when IAM refuses it.

## IAM Coverage

Every IAM API call is recorded as a management event, as CloudTrail
["logs all authenticated API requests to IAM"](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html):
one IAM ran, one IAM answered with an error, and, with `floci.services.iam.enforcement-enabled`, one IAM enforcement
refused.

- `eventSource` is `iam.amazonaws.com` and `awsRegion` the Region IAM signs for in the request's partition
  (`us-east-1` in `aws`). IAM is a global service, so only a trail with `IncludeGlobalServiceEvents` (the default)
  records its calls, and only a multi-Region trail or one whose home Region is that Region.
- `readOnly` is `true` for the actions AWS's service reference
  ([`iam.json`](https://servicereference.us-east-1.amazonaws.com/v1/iam/iam.json)) gives the Read or List access
  level, vendored as `readOnlyActions` in `iam-action-resources.json` by `make iam-action-resources-sync`.
- `requestParameters` holds the request's members, named with a lower first letter (`userName`, `policyArn`,
  `tags: [{"key": ..., "value": ...}]`), numbers and booleans typed as botocore's IAM model types them. A member the
  model marks sensitive (a password, a private key) is left out, and a request whose only members are sensitive
  (`ChangePassword`) has `"requestParameters": null`.
- `responseElements` is `null` for a failed call and for a read-only one, as CloudTrail
  "redacts the responseElements information" of a read-only event. Otherwise it holds the call's result
  (`{"accessKey": {...}}` for `CreateAccessKey`), numbers, booleans and timestamps typed as the model types them,
  timestamps written as CloudTrail writes them (`Oct 29, 2024 2:43:20 PM`), and without the members the model marks
  sensitive (`secretAccessKey`, a service-specific credential's password or secret, a virtual MFA device's seed).
- An error IAM models is recorded under its error shape's name: `NoSuchEntity` as `NoSuchEntityException`,
  `DeleteConflict` as `DeleteConflictException`, with IAM's message. A call IAM enforcement refuses, on its
  policies or because a `GetSessionToken` session without MFA cannot make it, is recorded as
  `errorCode: "AccessDenied"` and `"requestParameters": null`, with the message and the request ID the refusal
  answered with.
- `sourceIPAddress` is the address the request came from and `userAgent` its `User-Agent`; `requestID` is the one
  IAM answered with. `userIdentity` is the caller as it was before the call ran, so a key that deletes itself is
  still recorded as its user's.
- Like every management event, an IAM call also reaches the account's event history, which `LookupEvents` reads,
  whether or not a trail records it.

How each member is typed, which members are sensitive and each error's shape name are read from
`iam-cloudtrail-shapes.json`, which `make aws-data-sync` generates from the pinned botocore.

## SQS Coverage

The SQS calls CloudTrail records as management events are recorded, as the SQS Developer Guide
[lists them](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/logging-using-cloudtrail.html):
`AddPermission`, `CancelMessageMoveTask`, `CreateQueue`, `DeleteQueue`, `ListMessageMoveTasks`, `PurgeQueue`,
`RemovePermission`, `SetQueueAttributes`, `StartMessageMoveTask`, `TagQueue` and `UntagQueue`: one SQS ran, one SQS
answered with an error, and, with `floci.services.iam.enforcement-enabled`, one IAM enforcement refused. Each
reaches the account's event history whether or not a trail records it.

- `eventSource` is `sqs.amazonaws.com` and `awsRegion` the queue's Region.
- `readOnly` is `true` for `ListMessageMoveTasks` only, the one of them AWS's service reference
  ([`sqs.json`](https://servicereference.us-east-1.amazonaws.com/v1/sqs/sqs.json)) gives no Write, Permissions
  management or Tagging access level, vendored in `sqs-cloudtrail-events.json` by `make cloudtrail-events-sync`.
- `requestParameters` and `responseElements` hold the request's and the result's members, named with a lower first
  letter as the guide's event example names them (`queueUrl`, `mD5OfMessageBody`), a map's keys as sent
  (`"attributes": {"Policy": ...}`, `"tags": {"team": ...}`), typed as botocore's SQS model types them
  (`sqs-cloudtrail-shapes.json`). `responseElements` is `{"queueUrl": ...}` for `CreateQueue`,
  `{"taskHandle": ...}` for `StartMessageMoveTask`, and `null` for a call that answers nothing, for
  `ListMessageMoveTasks` and for a failed call.
- An error is recorded under its shape's name (`QueueDoesNotExist`), with SQS's message. A call IAM enforcement
  refuses is recorded as `AccessDenied` with `"requestParameters": null` and the message its refusal
  answers with.

Not recorded:

- SQS data events (`SendMessage`, `ReceiveMessage`, `DeleteMessage`, `ChangeMessageVisibility`, their batches,
  `GetQueueAttributes`, `GetQueueUrl`, `ListQueues`, `ListQueueTags`, `ListDeadLetterSourceQueues`), which AWS logs
  only for a trail whose advanced event selectors select the `AWS::SQS::Queue` resource type.
- A call made over SQS's Query protocol (`Action=CreateQueue` in a form body): botocore's SQS model no longer
  carries that protocol's member names, so its request cannot be read as the model's members. A call IAM enforcement
  refuses is recorded whichever protocol it uses.
- A call another service makes for the caller, such as a Step Functions task or an API Gateway integration.

## Secrets Manager Coverage

Every Secrets Manager call is recorded as a management event, as CloudTrail
["writes entries to your AWS CloudTrail log for all Secrets Manager operations"](https://docs.aws.amazon.com/secretsmanager/latest/userguide/cloudtrail_log_entries.html):
one Secrets Manager ran, one it answered with an error, and, with `floci.services.iam.enforcement-enabled`, one IAM
enforcement refused.

- `eventSource` is `secretsmanager.amazonaws.com` and `awsRegion` the request's Region.
- `readOnly` is `true` for the calls AWS's service reference
  ([`secretsmanager.json`](https://servicereference.us-east-1.amazonaws.com/v1/secretsmanager/secretsmanager.json))
  gives no Write, Permissions management or Tagging access level: `BatchGetSecretValue`, `DescribeSecret`,
  `GetRandomPassword`, `GetResourcePolicy`, `GetSecretValue`, `ListSecretVersionIds` and `ListSecrets`, vendored in
  `secretsmanager-cloudtrail-events.json` by `make cloudtrail-events-sync`.
- `requestParameters` and `responseElements` hold the request's and the result's members, named with a lower first
  letter (`secretId`, `filters: [{"key": ..., "values": [...]}]`), typed as botocore's Secrets Manager model types
  them (`"maxResults": 100`, `secretsmanager-cloudtrail-shapes.json`). The members the model marks sensitive are left
  out, as the API Reference says of `SecretString` and `SecretBinary`: "the service does not include it in AWS
  CloudTrail log entries". The secret's ARN is `arn`, as CloudTrail has written it since February 2024 (it was
  `aRN` before). `responseElements` is `null` for a read-only call, for a call that answers nothing and for a failed
  one.
- `BatchGetSecretValue` is recorded as one `BatchGetSecretValue` event, not one `GetSecretValue` event per secret.
- An error is recorded under its code (`ResourceNotFoundException`), with Secrets Manager's message. A call IAM
  enforcement refuses is recorded as `AccessDenied` with `"requestParameters": null` and the message its refusal
  answers with.

Its records reach EventBridge as every other record does ([EventBridge delivery](#eventbridge-delivery)).

A call another service makes to Secrets Manager for the caller, such as an API Gateway integration or a Step Functions
task, is recorded too, without the `invokedBy` that names that service on AWS. A timestamp in `responseElements`
(`deletionDate`) is written in epoch seconds, as Secrets Manager answers it.

Not recorded: the service events Secrets Manager logs for rotation, replication and version deletion
(`RotationSucceeded`, `StartSecretVersionDelete`, ...).

## KMS Coverage

Every KMS call is recorded as a management event, as CloudTrail
["logs all AWS KMS operations, including read-only operations, ... operations that manage KMS keys, ... and cryptographic operations"](https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html):
one KMS ran, one it answered with an error, and, with `floci.services.iam.enforcement-enabled`, one IAM enforcement
refused. Each record follows the guide's examples of that operation (`ct-<operation>.html`).

- `eventSource` is `kms.amazonaws.com`. `readOnly` is `true` for the reads AWS's service reference
  ([`kms.json`](https://servicereference.us-east-1.amazonaws.com/v1/kms/kms.json)) gives no mutating access level and for
  the [cryptographic operations](https://docs.aws.amazon.com/kms/latest/developerguide/kms-cryptography.html#cryptographic-operations)
  (`Encrypt`, `Decrypt`, `ReEncrypt`, `GenerateDataKey*`, `Sign`, `Verify`, `GenerateMac`, `VerifyMac`,
  `GenerateRandom`, `DeriveSharedSecret`), which the guide's examples record read-only
  (`kms-cloudtrail-events.json`, `make cloudtrail-events-sync`).
- `requestParameters` and `responseElements` hold the members with a lower first letter, typed as botocore's KMS
  model types them (`kms-cloudtrail-shapes.json`), without plaintext and without any binary member ("The ciphertext in
  the request and the plaintext in the response are omitted"), and a timestamp is written as the guide's examples write
  one (`"creationDate": "Aug 10, 2022, 10:38:27 PM"`). A `Decrypt` record always carries the key it used as `keyId`
  and its `encryptionAlgorithm`.
- `responseElements` is `null` for a read-only call, the cryptographic operations included, and carries the key's ARN
  as `keyId` for `CreateAlias`, `CreateGrant`, `DeleteAlias`, `DisableKey`, `EnableKey`, `EnableKeyRotation`,
  `ImportKeyMaterial`, `TagResource`, `UntagResource`, `UpdateAlias` and `UpdatePrimaryRegion`, as KMS does "even when
  the AWS KMS API operation doesn't return the key ARN". A `CreateGrant` record carries the grant's ID, not its token.
- `resources` lists the keys the call used as `AWS::KMS::Key`: the source and then the destination key of a
  `ReEncrypt`, the key then its alias for `CreateAlias`, the alias then its key for `UpdateAlias` and `DeleteAlias`,
  the primary key (not the replica) for `ReplicateKey`, and none (`[]`) for a call that uses no key, such as
  `ListAliases` or `GenerateRandom`.
- An error is recorded under its `__type` (`NotFoundException`); a call IAM enforcement refuses as `AccessDenied`
  with `"requestParameters": null` and the message its refusal answers with. A call
  another service makes to KMS through its API for the caller is recorded too, without `invokedBy`.

Not recorded: the `keyMaterialId` of a cryptographic operation's `additionalEventData`, the `CreateKey` entry a
`ReplicateKey` request also results in, the `DeleteKey` and `RotateKey`
events KMS logs when it deletes or rotates a key on its own (Floci does neither), and KMS calls other services make
internally for their own encryption (S3, Secrets Manager).

## CloudWatch Logs Coverage

The CloudWatch Logs calls CloudTrail records are recorded as management events, as the CloudWatch Logs guide
[lists them](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/logging_cw_api_calls_cwl.html) (`CreateLogGroup`,
`DeleteLogGroup`, `PutRetentionPolicy`, `PutSubscriptionFilter`, `DeleteSubscriptionFilter`, `CreateExportTask`,
`PutResourcePolicy`, `GetLogEvents`, `FilterLogEvents`, `StartQuery` and the rest): one CloudWatch Logs ran, one it
answered with an error, and, with `floci.services.iam.enforcement-enabled`, one IAM enforcement refused. A call the list
leaves out, such as `PutLogEvents`, is not recorded.

- `eventSource` is `logs.amazonaws.com`, and the record carries `"apiVersion": "20140328"`, as the guide's
  `CreateExportTask` example does.
- `readOnly` is `true` for the calls AWS's service reference
  ([`logs.json`](https://servicereference.us-east-1.amazonaws.com/v1/logs/logs.json)) gives no mutating access level
  (`logs-cloudtrail-events.json`, `make cloudtrail-events-sync`).
- `requestParameters` and `responseElements` hold the members as botocore's model names and types them
  (`logGroupName`, `"retentionInDays": 1`, `"taskId"`, `logs-cloudtrail-shapes.json`); `responseElements` is `null`
  for a read-only call, for a call that answers nothing and for a failed one.
- An error is recorded under its `__type` (`ResourceNotFoundException`); a call IAM enforcement refuses as `AccessDenied`
  with `"requestParameters": null` and the message its refusal answers with. A call an
  API Gateway integration makes is recorded too, without `invokedBy`.

## EC2 Coverage

"All Amazon EC2 API actions are logged as management events"
([Amazon EC2 API Reference](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/using-cloudtrail.html)), but an EC2
record writes a call's members in EC2's own schema rather than botocore's, which no published source carries. Floci
records the EC2 calls a record shows, as it shows them, a record from 2024 or later first, then an AWS guide's example,
then an older record (`ec2-cloudtrail-events.json`):

- instances: `RunInstances`, `StartInstances`, `StopInstances`, `TerminateInstances`, `ModifyInstanceAttribute`,
  `GetPasswordData`;
- security groups: `CreateSecurityGroup`, `DeleteSecurityGroup`, `AuthorizeSecurityGroupIngress`,
  `AuthorizeSecurityGroupEgress`, `RevokeSecurityGroupIngress`, `RevokeSecurityGroupEgress`,
  `ModifySecurityGroupRules`;
- volumes and snapshots: `CreateVolume`, `DeleteVolume`, `AttachVolume`, `DetachVolume`, `CreateSnapshot`,
  `CopySnapshot`, `DeleteSnapshot`, `ModifySnapshotAttribute`;
- images and key pairs: `CreateImage`, `CopyImage`, `DeregisterImage`, `ModifyImageAttribute`, `CreateKeyPair`,
  `ImportKeyPair`;
- network ACLs and flow logs: `CreateNetworkAcl`, `DeleteNetworkAcl`, `CreateNetworkAclEntry`,
  `ReplaceNetworkAclEntry`, `DeleteNetworkAclEntry`, `CreateFlowLogs`, `DeleteFlowLogs`.

Other EC2 calls are not recorded yet.

- `requestParameters` follow those records: a list is `{"items": [...]}` and an empty one `{}`
  (`"instancesSet": {"items": [{"instanceId": ...}]}`, `"ipPermissions": {"items": [{"ipRanges": {"items": [{"cidrIp": ...}]}, "groups": {}}]}`),
  tags are `"tagSpecificationSet": {"items": [{"resourceType": ..., "tags": [{"key": ..., "value": ...}]}]}`, and a
  member is named and typed as its record shows it rather than as the request sends it (`CreateVolume`'s `zone` and its
  `size` as text, `CreateSecurityGroup`'s `groupDescription`, a network ACL entry's `aclProtocol`). Defaults the records
  show are written when the request leaves them out: `RunInstances`'s `blockDeviceMapping`, `disableApiStop`,
  `disableApiTermination` and `monitoring`, `DeleteSnapshot`'s and `DetachVolume`'s `force`, `DeleteVolume`'s
  `reportVolumeFailure`, `AttachVolume`'s `deleteOnTermination`, `CreateKeyPair`'s `keyType` (`rsa`) and `keyFormat`
  (`pem`), and a network ACL entry's empty `icmpTypeCode` and `portRange`. `ModifyInstanceAttribute` writes user data as
  `"<sensitiveDataRemoved>"` and `ModifySnapshotAttribute` names its attribute `CREATE_VOLUME_PERMISSION`.
  `CreateFlowLogs`, `DeleteFlowLogs` and `ModifySecurityGroupRules` write their request and answer as their XML
  (`{"DeleteFlowLogsRequest": {"FlowLogId": {"content": ..., "tag": 1}}}`). A member no record shows (a key pair,
  security groups or an instance profile on `RunInstances`, another attribute on `ModifyInstanceAttribute`, a
  snapshot's or a copied image's description, an ICMP type on a network ACL entry) is left out.
- `responseElements` is the call's answer with its XML names (`instancesSet`, `securityGroupRuleSet`), lists in `items`,
  the answer's `requestId`, a boolean result as `_return`, timestamps in epoch milliseconds and key material as
  `"<sensitiveDataRemoved>"` (`ec2-cloudtrail-shapes.json`), and where a record shows otherwise, as it shows it:
  `CreateVolume`'s `zone` and `size` and `CreateSnapshot`'s `volumeSize` as text, a network ACL's `isDefault` and its
  entries' `aclProtocol`, and only the members their records show for `CreateVolume`, `CreateSnapshot`, `AttachVolume`
  and `DetachVolume`; `null` for a read-only call (`GetPasswordData`) and a failed one.
- An error is recorded as `Client.<code>` (`Client.InvalidNetworkAclID.NotFound`); a call IAM enforcement refuses as
  `Client.UnauthorizedOperation` with EC2's message and its members, as AWS keeps them for a refused EC2 call.

## Lambda Coverage

"Lambda supports logging the following actions as management events in CloudTrail log files"
([Lambda Developer Guide](https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html)). Floci records
those calls (`lambda-cloudtrail-events.json`) under the name a record gives each: most carry the API version they are
served under (`CreateFunction20150331`, `UpdateFunctionCode20150331v2`, `PublishLayerVersion20181031`), the newer ones
their own (`CreateFunctionUrlConfig`). Floci also records the calls the guide leaves out that real logs record as
management events: `GetAccountSettings20160819`, `GetEventSourceMapping20150331`, `GetFunctionCodeSigningConfig`,
`GetFunctionEventInvokeConfig`, `ListAliases20150331`, `ListLayers20181031`, `ListTags20170331` and
`ListVersionsByFunction20150331`. `GetLayerVersionPolicy` is not recorded: no record shows its event name, which the
guide gives without a version where records of its neighbors carry one.

- `requestParameters` are the call's members from its path, its query and its body, with a lower first letter and
  typed as botocore's Lambda model types them (`"functionName"`, `"maxItems": 10000`). The members the model marks
  sensitive are left out, as the guide says of `Environment` and `ZipFile`: `"code": {}`, `"environment": {}`.
  `CreateFunction` and `UpdateFunctionConfiguration` always write `"environment": {}`. `UpdateFunctionCode` names the
  function by its ARN, adds its `fullyQualifiedArn`, and writes `"dryRun": false` when the request leaves it out.
- `responseElements` is the answer in the same form, with `"environment": {}` in a function's configuration; `null`
  for a read-only call, a call that answers nothing (`DeleteFunction`, `RemovePermission`) and a failed one.
  `PublishLayerVersion` carries `"additionalEventData": {"signatureStatus": "VALID"}`.
- A failed call keeps its members, under its error's type (`ResourceNotFoundException`); a call IAM enforcement refuses
  is recorded as `AccessDenied` with `"requestParameters": null`.
- `Invoke` is a data event, not recorded here.

## Sign-in and IAM Identity Center Coverage

The calls that issue credentials to a person are recorded, each under the event source AWS records it with. None
records a secret: a token, a client secret, an assertion or a credential is either left out or written
`HIDDEN_DUE_TO_SECURITY_REASONS`, as AWS writes it.

- **AWS Sign-In** (`aws login`), as the
  [IAM User Guide's records](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html#cloudtrail-integration_examples-signin)
  show: `AuthorizeOAuth2Access` when the consent page grants the code, with `scope`, `redirect_uri`,
  `code_challenge_method` and `client_id`, and `CreateOAuth2Token` when the CLI exchanges a code or a refresh token,
  with `client_id` alone. Both are `signin.amazonaws.com`, read-only, with `"responseElements": null` and
  `"additionalEventData": {"success": "true", "x-amzn-vpce-id": ""}`, and are the account root user's, whom Floci's
  sign-in grants.
- **OIDC**, as the
  [IAM Identity Center guide lists it](https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-info-in-cloudtrail.html#cloudtrail-events-oidc-operations):
  `CreateToken` (`sso.amazonaws.com`) and `CreateTokenWithIAM` (`sso-oauth.amazonaws.com`); `RegisterClient` and
  `StartDeviceAuthorization` are not in the list and are not recorded. `CreateToken` is the user's
  (`"type": "IdentityCenterUser"`, below), keeps `clientId`, `grantType` and `deviceCode`, hides `clientSecret`, and
  answers `tokenType` and `expiresIn` with the tokens hidden, the Identity Store in `resources`
  ([example](https://docs.aws.amazon.com/singlesignon/latest/userguide/understanding-sso-entries.html)).
  `CreateTokenWithIAM` is its signer's, keeps the request's members with `code`, `assertion`, `subjectToken`,
  `refreshToken` and `codeVerifier` hidden
  ([example](https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-cloudtrail-use-cases.html#identifying-user-background-session-details)),
  answers `tokenType`, `expiresIn` and `issuedTokenType` with the tokens hidden, names the application in `resources`,
  and the token's user in `additionalEventData` (`identitystore:UserId`, `identitystore:IdentityStoreArn`,
  `identitycenter:CredentialId`). A failed `CreateTokenWithIAM` is recorded under its exception name
  (`InvalidRequestException`) with its request; both are write events.
- **AWS access portal**, as the guide
  [lists it](https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-info-in-cloudtrail.html#cloudtrail-events-access-portal-operations):
  `ListAccounts`, `ListAccountRoles` and `GetRoleCredentials`, `sso.amazonaws.com`, read-only, as
  `"eventType": "AwsServiceEvent"` with `"requestParameters": null` and `"responseElements": null`: the role
  credentials are never recorded. `ListAccountRoles` carries `"serviceEventDetails": {"account_id": ...}` and
  `GetRoleCredentials` `{"role_name": ..., "account_id": ...}`.
- The user behind an IAM Identity Center token is `"type": "IdentityCenterUser"` with the account, `onBehalfOf`
  (`userId`, `identityStoreArn`) and `credentialId`, as AWS
  [names it](https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-cloudtrail-use-cases.html#user-session-iam-identity-center)
  since July 2025. `credentialId` is "the ID of the access token": Floci derives it from the token, one way, so
  the same token gives the same `credentialId` in `CreateToken` and in the portal calls made with it.

Not recorded yet: a failed sign-in, `CreateToken` or portal call, the consent page's cancellation, `Logout`, and a
`CreateTokenWithIAM` IAM enforcement refuses.

## EventBridge delivery

"CloudTrail sends the following types of events to the default EventBridge event bus", the first of them
`AWS API Call via CloudTrail`, and "To record events with one of the CloudTrail `detail-type` values, you must enable
a CloudTrail trail with logging"
([EventBridge User Guide](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event-cloudtrail.html)).
Every record a logging trail selects, management or data event, is also put on the default bus once, however many
trails select it:

- `source` is `aws.<service>` for the record's `<service>.amazonaws.com` (`aws.lambda`, `aws.iam`), `detail-type`
  follows the record's `eventType` (`AWS API Call via CloudTrail` for `AwsApiCall`), `account` and `region` are the
  record's, `resources` is `[]`, and `detail` is the record, as the Amazon EBS User Guide's `detachVolume` example
  (2024) shows one.
- A global service's record is logged in US East (N. Virginia), so an IAM call reaches the default bus there, whatever
  Region it was signed for.
- A record over 256 KB is not sent: "CloudTrail does not send these events to CloudWatch Logs or EventBridge".
- A rule in the default `ENABLED` state matches write management events and data events; a read-only management event
  is matched only by a rule in the `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` state, on the default bus or on a
  bus a rule forwards it to.
- Delivery runs in the background on two workers with a bounded queue of 256 events, so a slow target never holds the
  call. It is best effort: a full queue drops the event, and an emulator reset discards queued events and waits up to
  30 seconds for active deliveries before storage is cleared.

## Management events and selectors

New trails include management events by default. Basic selectors honor `IncludeManagementEvents`, `ReadWriteType`
(against each event's `readOnly`), and source exclusions. Advanced selectors evaluate `eventCategory`, `eventSource`,
`eventName`, `readOnly`, `eventType`, and `userIdentity.arn`; unsupported fields do not match these records.

Records have `eventCategory: Management` and `managementEvent: true`. Buffers and background S3 delivery retain the
originating account, including when different accounts use the same trail name. Multi-region trails cover regions
within their own partition.

## Event History

`LookupEvents` reads the event history: every management event Floci records, in the caller's
account and region, whether or not a trail is logging, as on AWS. Today those are the Secrets Manager
`PutSecretValue` and `UpdateSecret` writes above. Events come back newest first, at most 50 a page
with a `NextToken` for the rest (as on AWS, the token is accepted only with the same parameters), and can be narrowed by `StartTime`, `EndTime` and one
`LookupAttributes` entry (`EventId`, `EventName`, `EventSource`, `ReadOnly`, `Username` or
`AccessKeyId`). Each event carries `CloudTrailEvent`, the full record as a trail delivers it.

The history keeps 90 days and at most 10,000 events per account and region, in memory: it does not
survive a restart, and an emulator reset empties it. Records name no resources, so `Resources` is empty and a `ResourceType` or
`ResourceName` attribute matches nothing. Floci records no Insights events, so `EventCategory: insight`
returns an empty page; any other category is refused with `InvalidEventCategoryException`.

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
