package io.floci.aws.services.ec2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AccountResolver;
import io.floci.aws.core.common.RequestSourceAddress;
import io.floci.aws.core.common.ServicePrincipals;
import io.floci.aws.core.common.XmlParser;
import io.floci.aws.services.cloudtrail.CloudTrailEventCatalog;
import io.floci.aws.services.cloudtrail.CloudTrailService;
import io.floci.aws.services.cloudtrail.CloudTrailShapes;
import io.floci.aws.services.cloudtrail.ManagementEventSource;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * Records EC2 calls as CloudTrail management events. "All Amazon EC2 API actions are logged as
 * management events" (https://docs.aws.amazon.com/AWSEC2/latest/APIReference/using-cloudtrail.html),
 * but an EC2 record writes a call's members in EC2's own schema, not botocore's: a list of instances
 * is {@code "instancesSet": {"items": [{"instanceId": ...}]}}, an empty list {@code {}}. No published
 * source carries that schema any more, so Floci records only the calls whose record shows it, each
 * mapped from its Query form in {@link #requestParameters} after the record it cites: a capture from
 * 2024 or later, else an AWS guide's example, else an older capture. They are listed in the vendored
 * {@code aws/ec2-cloudtrail-events.json} ({@link CloudTrailEventCatalog}), which also says which are
 * read-only (the Service Reference's access level).
 *
 * <p>{@code responseElements} is the call's XML answer as {@link CloudTrailShapes#ec2Result} writes
 * it, with the changes {@link #responseElements} makes where a record names or types a member
 * otherwise, null for a read-only call and a failed one. The newer calls in {@link #XML_STYLE} are
 * written instead as their own request and answer XML ({@link #xmlStyleRequest}). A failed call is
 * recorded under its EC2 code
 * prefixed {@code Client.}, and a call IAM enforcement refuses as
 * {@code Client.UnauthorizedOperation} with the message EC2 answers ("You are not authorized to
 * perform this operation. User: ...") and its members, as 2024 records of a refused RunInstances and
 * GetPasswordData show them. A member a record does not show is left out of
 * {@code requestParameters} rather than guessed.
 */
@ApplicationScoped
public class Ec2CloudTrailEvents implements ManagementEventSource {

    private static final Logger LOG = Logger.getLogger(Ec2CloudTrailEvents.class);
    private static final String SERVICE = "ec2";
    private static final String EVENT_SOURCE = ServicePrincipals.of(SERVICE);
    /** What an EC2 record writes in place of a sensitive member ({@code userData}). */
    static final String SENSITIVE = "<sensitiveDataRemoved>";
    private static final String EC2_NAMESPACE = "http://ec2.amazonaws.com/doc/2016-11-15/";
    /**
     * The calls a record writes as their request and answer XML rather than in EC2's schema:
     * DeleteFlowLogs (2024-10-08 and 2024-07-31), CreateFlowLogs (2023-07-10) and
     * ModifySecurityGroupRules (2023-06-24).
     */
    private static final Set<String> XML_STYLE = Set.of("CreateFlowLogs", "DeleteFlowLogs",
            "ModifySecurityGroupRules");
    private static final Pattern INTEGER = Pattern.compile("-?\\d+");

    private final CloudTrailService cloudTrail;
    private final AccountResolver accounts;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;

    @Inject
    public Ec2CloudTrailEvents(CloudTrailService cloudTrail, AccountResolver accounts,
                               CurrentVertxRequest currentRequest, ObjectMapper mapper) {
        this.cloudTrail = cloudTrail;
        this.accounts = accounts;
        this.currentRequest = currentRequest;
        this.mapper = mapper;
    }

    /** Runs {@code call}, the EC2 call {@code action} signed with {@code authorization}, and records it. */
    public Response recorded(String action, MultivaluedMap<String, String> params, String region,
                             String authorization, Supplier<Response> call) {
        Response response = call.get();
        CloudTrailEventCatalog catalog = CloudTrailEventCatalog.of(SERVICE);
        if (!catalog.isManagementEvent(action)) {
            return response;
        }
        try {
            String xml = response.getEntity() instanceof String text ? text : null;
            String errorCode = null;
            String errorMessage = null;
            ObjectNode result = null;
            if (response.getStatus() >= 400) {
                XmlParser.XmlElement error = xml == null ? null : XmlParser.extractElementTree(xml, "Error");
                String code = error == null || error.child("Code") == null ? null : error.child("Code").text();
                errorCode = code == null || response.getStatus() >= 500 ? code : "Client." + code;
                errorMessage = error == null || error.child("Message") == null ? null : error.child("Message").text();
            } else if (!catalog.isReadOnly(action)) {
                result = XML_STYLE.contains(action) ? xmlStyleResult(action, xml)
                        : responseElements(action, CloudTrailShapes.of(SERVICE).ec2Result(action, xml));
            }
            cloudTrail.emitManagementEvent(event(action, requestParameters(action, first(params)),
                    accounts.extractAccessKeyId(authorization), region, currentRequest.getCurrent(), result,
                    errorCode, errorMessage));
        } catch (RuntimeException e) {
            // The call is answered either way; a record that could not be written is logged, not raised.
            LOG.warnv(e, "Failed to record CloudTrail call {0}", action);
        }
        return response;
    }

    @Override
    public String credentialScope() {
        return SERVICE;
    }

    @Override
    public CloudTrailService.ManagementEventInput refused(String operation, String accessKeyId, String region,
                                                          RoutingContext routingContext, Response refusal) {
        return refused(operation, accessKeyId, region, routingContext, refusal, Map.of());
    }

    /**
     * A refused EC2 call keeps its members, as the 2024 records of a refused RunInstances show, and its
     * refusal's code and message, the code under the {@code Client.} prefix those records write
     * ({@code Client.UnauthorizedOperation}).
     */
    @Override
    public CloudTrailService.ManagementEventInput refused(String operation, String accessKeyId, String region,
                                                          RoutingContext routingContext, Response refusal,
                                                          Map<String, String> formParameters) {
        if (!CloudTrailEventCatalog.of(SERVICE).isManagementEvent(operation)) {
            return null;
        }
        String xml = refusal != null && refusal.getEntity() instanceof String body ? body : "";
        String code = XmlParser.extractFirst(xml, "Code", null);
        return event(operation, requestParameters(operation, formParameters), accessKeyId, region, routingContext,
                null, code == null ? null : "Client." + code, XmlParser.extractFirst(xml, "Message", null));
    }

    /**
     * The members of {@code action}'s request as its record writes them, from the Query form
     * {@code p}: each mapping follows the record of that call it cites.
     */
    ObjectNode requestParameters(String action, Map<String, String> p) {
        if (XML_STYLE.contains(action)) {
            return xmlStyleRequest(action, p);
        }
        ObjectNode read = mapper.createObjectNode();
        switch (action) {
            // RunInstances, 2024-09-11 and 2024-08-01: the image and counts in instancesSet, and
            // blockDeviceMapping, disableApiStop, disableApiTermination and monitoring with their
            // defaults when the request leaves them out.
            case "RunInstances" -> {
                read.set("blockDeviceMapping", mapper.createObjectNode());
                text(read, "clientToken", p.get("ClientToken"));
                read.put("disableApiStop", Boolean.parseBoolean(p.getOrDefault("DisableApiStop", "false")));
                read.put("disableApiTermination",
                        Boolean.parseBoolean(p.getOrDefault("DisableApiTermination", "false")));
                text(read, "instanceType", p.get("InstanceType"));
                ObjectNode launch = mapper.createObjectNode();
                text(launch, "imageId", p.get("ImageId"));
                number(launch, "maxCount", p.get("MaxCount"));
                number(launch, "minCount", p.get("MinCount"));
                read.set("instancesSet", items(launch));
                read.putObject("monitoring").put("enabled",
                        Boolean.parseBoolean(p.getOrDefault("Monitoring.Enabled", "false")));
                text(read, "subnetId", p.get("SubnetId"));
                tagSpecifications(read, p);
            }
            // StartInstances, 2024-08-01.
            case "StartInstances" -> read.set("instancesSet", instances(p));
            // StopInstances, 2024-08-01: force as sent.
            case "StopInstances" -> {
                bool(read, "force", p.get("Force"));
                read.set("instancesSet", instances(p));
            }
            // TerminateInstances, 2025-03-07: force and skipOsShutdown false when left out.
            case "TerminateInstances" -> {
                read.set("instancesSet", instances(p));
                read.put("force", Boolean.parseBoolean(p.getOrDefault("Force", "false")));
                read.put("skipOsShutdown", Boolean.parseBoolean(p.getOrDefault("SkipOsShutdown", "false")));
            }
            // ModifyInstanceAttribute, 2024-08-01: the instance, and the user data hidden.
            case "ModifyInstanceAttribute" -> {
                text(read, "instanceId", p.get("InstanceId"));
                if (p.containsKey("UserData.Value")) {
                    read.put("userData", SENSITIVE);
                }
            }
            // AuthorizeSecurityGroupIngress, 2024-10-14 (IpPermissions) and 2024-08-01 (a rule
            // given by its top-level members, with "ipPermissions": {}); AuthorizeSecurityGroupEgress,
            // 2024-10-30; RevokeSecurityGroupIngress, 2023-07-10 (top-level members);
            // RevokeSecurityGroupEgress, 2023-07-10 and 2021-01-12 (IpPermissions, an IPv6 range
            // written cidrIpv6).
            case "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupIngress",
                 "RevokeSecurityGroupEgress" -> {
                text(read, "groupId", p.get("GroupId"));
                text(read, "groupName", p.get("GroupName"));
                text(read, "cidrIp", p.get("CidrIp"));
                text(read, "ipProtocol", p.get("IpProtocol"));
                number(read, "fromPort", p.get("FromPort"));
                number(read, "toPort", p.get("ToPort"));
                read.set("ipPermissions", permissions(p));
            }
            // ModifyImageAttribute, 2024-10-10 (remove) and 2024-08-01 (add).
            case "ModifyImageAttribute" -> {
                ObjectNode permission = permissionChange(p, "LaunchPermission");
                text(read, "attributeType", p.getOrDefault("Attribute", permission == null ? null : "launchPermission"));
                text(read, "imageId", p.get("ImageId"));
                if (permission != null) {
                    read.set("launchPermission", permission);
                }
            }
            // ModifySnapshotAttribute, 2024-10-15 (remove) and 2024-08-01 (add): the attribute
            // written CREATE_VOLUME_PERMISSION.
            case "ModifySnapshotAttribute" -> {
                ObjectNode permission = permissionChange(p, "CreateVolumePermission");
                String attribute = p.get("Attribute");
                text(read, "attributeType", "createVolumePermission".equals(attribute) || attribute == null && permission != null
                        ? "CREATE_VOLUME_PERMISSION" : attribute);
                if (permission != null) {
                    read.set("createVolumePermission", permission);
                }
                text(read, "snapshotId", p.get("SnapshotId"));
            }
            // DeleteNetworkAcl and DeleteNetworkAclEntry, 2024-10-14.
            case "DeleteNetworkAcl" -> text(read, "networkAclId", p.get("NetworkAclId"));
            case "DeleteNetworkAclEntry" -> {
                bool(read, "egress", p.get("Egress"));
                text(read, "networkAclId", p.get("NetworkAclId"));
                number(read, "ruleNumber", p.get("RuleNumber"));
            }
            // GetPasswordData, 2024-10-11 and 2024-07-30.
            case "GetPasswordData" -> text(read, "instanceId", p.get("InstanceId"));
            // CreateSecurityGroup, 2023-07-10 and 2021-01-12: the description written groupDescription.
            case "CreateSecurityGroup" -> {
                text(read, "groupName", p.get("GroupName"));
                text(read, "groupDescription", p.get("GroupDescription"));
                text(read, "vpcId", p.get("VpcId"));
                tagSpecifications(read, p);
            }
            // DeleteSecurityGroup, 2023-07-10.
            case "DeleteSecurityGroup" -> text(read, "groupId", p.get("GroupId"));
            // CreateSnapshot, 2023-07-10 and 2023-03-20.
            case "CreateSnapshot" -> {
                text(read, "volumeId", p.get("VolumeId"));
                tagSpecifications(read, p);
            }
            // CopySnapshot, 2020-09-25 and 2020-08-20 (refused and failed): the destination and the
            // presigned URL an SDK adds, as sent.
            case "CopySnapshot" -> {
                text(read, "sourceRegion", p.get("SourceRegion"));
                text(read, "sourceSnapshotId", p.get("SourceSnapshotId"));
                text(read, "destinationRegion", p.get("DestinationRegion"));
                text(read, "presignedUrl", p.get("PresignedUrl"));
                tagSpecifications(read, p);
            }
            // DeleteSnapshot, 2024-01-18 and 2023-07-10: force, which the request has no member
            // for, false.
            case "DeleteSnapshot" -> {
                text(read, "snapshotId", p.get("SnapshotId"));
                read.put("force", false);
            }
            // CreateVolume, 2023-07-10, and the AWS KMS Developer Guide's example (volumeType,
            // encrypted): the size written as text, the zone written zone.
            case "CreateVolume" -> {
                text(read, "size", p.get("Size"));
                text(read, "zone", p.get("AvailabilityZone"));
                text(read, "volumeType", p.get("VolumeType"));
                bool(read, "encrypted", p.get("Encrypted"));
                tagSpecifications(read, p);
                text(read, "clientToken", p.get("ClientToken"));
            }
            // DeleteVolume, 2023-07-10: reportVolumeFailure, which the request has no member for, false.
            case "DeleteVolume" -> {
                text(read, "volumeId", p.get("VolumeId"));
                read.put("reportVolumeFailure", false);
            }
            // AttachVolume, 2020-09-25 and 2020-06-11 (refused and failed): deleteOnTermination,
            // which the request has no member for, false.
            case "AttachVolume" -> {
                text(read, "volumeId", p.get("VolumeId"));
                text(read, "instanceId", p.get("InstanceId"));
                text(read, "device", p.get("Device"));
                read.put("deleteOnTermination", false);
            }
            // DetachVolume, the Amazon EBS User Guide's example (2024-03-18) and 2020-03-03: force
            // false when left out.
            case "DetachVolume" -> {
                text(read, "volumeId", p.get("VolumeId"));
                read.put("force", Boolean.parseBoolean(p.getOrDefault("Force", "false")));
            }
            // CreateKeyPair, the CloudTrail User Guide's example (2023-07-19): keyType rsa and
            // keyFormat pem, EC2's defaults, when left out.
            case "CreateKeyPair" -> {
                text(read, "keyName", p.get("KeyName"));
                read.put("keyType", p.getOrDefault("KeyType", "rsa"));
                read.put("keyFormat", p.getOrDefault("KeyFormat", "pem"));
                tagSpecifications(read, p);
            }
            // ImportKeyPair, 2020-09-08 (refused): the public key as sent, base64-encoded.
            case "ImportKeyPair" -> {
                text(read, "keyName", p.get("KeyName"));
                text(read, "publicKeyMaterial", p.get("PublicKeyMaterial"));
                tagSpecifications(read, p);
            }
            // CreateImage, 2020-08-19 (refused).
            case "CreateImage" -> {
                text(read, "instanceId", p.get("InstanceId"));
                text(read, "name", p.get("Name"));
                text(read, "description", p.get("Description"));
                tagSpecifications(read, p);
            }
            // CopyImage, 2020-05-12 (refused).
            case "CopyImage" -> {
                text(read, "sourceRegion", p.get("SourceRegion"));
                text(read, "sourceImageId", p.get("SourceImageId"));
                text(read, "name", p.get("Name"));
                tagSpecifications(read, p);
            }
            // DeregisterImage, 2023-07-10.
            case "DeregisterImage" -> text(read, "imageId", p.get("ImageId"));
            // CreateNetworkAcl, 2021-01-12.
            case "CreateNetworkAcl" -> {
                text(read, "vpcId", p.get("VpcId"));
                tagSpecifications(read, p);
            }
            // CreateNetworkAclEntry and ReplaceNetworkAclEntry, 2021-01-12: the protocol written
            // aclProtocol, the ports as numbers, and icmpTypeCode and portRange {} when left out.
            case "CreateNetworkAclEntry", "ReplaceNetworkAclEntry" -> {
                text(read, "networkAclId", p.get("NetworkAclId"));
                number(read, "ruleNumber", p.get("RuleNumber"));
                bool(read, "egress", p.get("Egress"));
                text(read, "ruleAction", p.get("RuleAction"));
                if (!hasPrefix(p, "Icmp.")) {
                    read.putObject("icmpTypeCode");
                }
                ObjectNode ports = read.putObject("portRange");
                number(ports, "from", p.get("PortRange.From"));
                number(ports, "to", p.get("PortRange.To"));
                text(read, "aclProtocol", p.get("Protocol"));
                text(read, "cidrBlock", p.get("CidrBlock"));
            }
            default -> {
                return null;
            }
        }
        return read.isEmpty() ? null : read;
    }

    /** {@code {"items": [...]}} of the instances {@code InstanceId.N} names. */
    private ObjectNode instances(Map<String, String> p) {
        ArrayNode ids = mapper.createArrayNode();
        for (int i = 1; p.containsKey("InstanceId." + i); i++) {
            ids.addObject().put("instanceId", p.get("InstanceId." + i));
        }
        return items(ids);
    }

    /** A security group's {@code ipPermissions}, from {@code IpPermissions.N}. */
    private ObjectNode permissions(Map<String, String> p) {
        ArrayNode rules = mapper.createArrayNode();
        for (int i = 1; hasPrefix(p, "IpPermissions." + i + "."); i++) {
            String prefix = "IpPermissions." + i + ".";
            ObjectNode rule = rules.addObject();
            text(rule, "ipProtocol", p.get(prefix + "IpProtocol"));
            number(rule, "fromPort", p.get(prefix + "FromPort"));
            number(rule, "toPort", p.get(prefix + "ToPort"));
            rule.set("groups", indexed(p, prefix + "Groups.", "GroupId", "groupId", "UserId", "userId"));
            rule.set("ipRanges", indexed(p, prefix + "IpRanges.", "CidrIp", "cidrIp", "Description", "description"));
            rule.set("ipv6Ranges", indexed(p, prefix + "Ipv6Ranges.", "CidrIpv6", "cidrIpv6", "Description",
                    "description"));
            rule.set("prefixListIds", indexed(p, prefix + "PrefixListIds.", "PrefixListId", "prefixListId",
                    "Description", "description"));
        }
        return items(rules);
    }

    /**
     * {@code {"add": {"items": [...]}}} or {@code {"remove": ...}} of the accounts and groups
     * {@code <name>.Add.N} and {@code <name>.Remove.N} name, or of the legacy {@code UserId.N} and
     * {@code UserGroup.N} with {@code OperationType}; null when the request changes none.
     */
    private ObjectNode permissionChange(Map<String, String> p, String name) {
        ObjectNode change = mapper.createObjectNode();
        for (String operation : new String[] {"Add", "Remove"}) {
            ArrayNode entries = permissionEntries(p, name + "." + operation + ".");
            if (!entries.isEmpty()) {
                change.set(operation.toLowerCase(), items(entries));
            }
        }
        String legacy = p.get("OperationType");
        if (change.isEmpty() && legacy != null) {
            ArrayNode entries = mapper.createArrayNode();
            for (int i = 1; p.containsKey("UserId." + i); i++) {
                entries.addObject().put("userId", p.get("UserId." + i));
            }
            for (int i = 1; p.containsKey("UserGroup." + i); i++) {
                entries.addObject().put("group", p.get("UserGroup." + i));
            }
            if (!entries.isEmpty()) {
                change.set(legacy.toLowerCase(), items(entries));
            }
        }
        return change.isEmpty() ? null : change;
    }

    private ArrayNode permissionEntries(Map<String, String> p, String prefix) {
        ArrayNode entries = mapper.createArrayNode();
        for (int i = 1; hasPrefix(p, prefix + i + "."); i++) {
            ObjectNode entry = entries.addObject();
            text(entry, "userId", p.get(prefix + i + ".UserId"));
            text(entry, "group", p.get(prefix + i + ".Group"));
        }
        return entries;
    }

    /** {@code {"items": [...]}} of {@code <prefix>N.<wire>} entries, each member renamed as given. */
    private ObjectNode indexed(Map<String, String> p, String prefix, String... wireAndRecordNames) {
        ArrayNode entries = mapper.createArrayNode();
        for (int i = 1; hasPrefix(p, prefix + i + "."); i++) {
            ObjectNode entry = entries.addObject();
            for (int n = 0; n < wireAndRecordNames.length; n += 2) {
                text(entry, wireAndRecordNames[n + 1], p.get(prefix + i + "." + wireAndRecordNames[n]));
            }
        }
        return items(entries);
    }

    private ObjectNode items(ObjectNode only) {
        ArrayNode list = mapper.createArrayNode();
        list.add(only);
        return items(list);
    }

    /** An EC2 record's list: {@code {"items": [...]}}, and {@code {}} when it holds nothing. */
    private ObjectNode items(ArrayNode list) {
        ObjectNode wrapped = mapper.createObjectNode();
        if (!list.isEmpty()) {
            wrapped.set("items", list);
        }
        return wrapped;
    }

    /**
     * {@code tagSpecificationSet}, {@code {"items": [{"resourceType", "tags": [{"key", "value"}]}]}},
     * from {@code TagSpecification.N}, as records of RunInstances (2024-09-11), CreateSecurityGroup,
     * CreateSnapshot and CreateVolume (2023-07-10) and CreateNetworkAcl (2021-01-12) write it.
     */
    private void tagSpecifications(ObjectNode read, Map<String, String> p) {
        ArrayNode specifications = mapper.createArrayNode();
        for (int i = 1; p.containsKey("TagSpecification." + i + ".ResourceType"); i++) {
            ObjectNode specification = specifications.addObject();
            specification.put("resourceType", p.get("TagSpecification." + i + ".ResourceType"));
            ArrayNode tags = specification.putArray("tags");
            for (int j = 1; p.containsKey("TagSpecification." + i + ".Tag." + j + ".Key"); j++) {
                tags.addObject().put("key", p.get("TagSpecification." + i + ".Tag." + j + ".Key"))
                        .put("value", p.getOrDefault("TagSpecification." + i + ".Tag." + j + ".Value", ""));
            }
        }
        if (!specifications.isEmpty()) {
            read.set("tagSpecificationSet", items(specifications));
        }
    }

    /**
     * {@code result} as the record of {@code action} writes it where it names, types or keeps its
     * members otherwise than the XML answer: CreateVolume's (2023-07-10) size as text and its zone
     * written zone, CreateSnapshot's (2023-07-10 and 2023-03-20) volumeSize as text, each without
     * the members its records do not show, DetachVolume's (the Amazon EBS User Guide's example,
     * 2024-03-18) and AttachVolume's, the same VolumeAttachment, without deleteOnTermination, and
     * CreateNetworkAcl's (2021-01-12) isDefault, and each entry's aclProtocol, icmpTypeCode and
     * portRange.
     */
    private ObjectNode responseElements(String action, ObjectNode result) {
        if (result == null) {
            return null;
        }
        switch (action) {
            case "CreateVolume" -> {
                rename(result, "availabilityZone", "zone");
                asText(result, "size");
                result.retain("requestId", "volumeId", "size", "zone", "status", "createTime", "volumeType", "iops",
                        "encrypted", "tagSet", "multiAttachEnabled");
            }
            case "CreateSnapshot" -> {
                asText(result, "volumeSize");
                result.retain("requestId", "snapshotId", "volumeId", "status", "startTime", "ownerId", "volumeSize",
                        "encrypted", "tagSet");
            }
            case "AttachVolume", "DetachVolume" ->
                    result.retain("requestId", "volumeId", "instanceId", "device", "status", "attachTime");
            case "CreateNetworkAcl" -> {
                if (result.get("networkAcl") instanceof ObjectNode acl) {
                    rename(acl, "default", "isDefault");
                    for (JsonNode entry : acl.path("entrySet").path("items")) {
                        if (entry instanceof ObjectNode rule) {
                            rename(rule, "protocol", "aclProtocol");
                            if (!rule.has("icmpTypeCode")) {
                                rule.putObject("icmpTypeCode");
                            }
                            if (!rule.has("portRange")) {
                                rule.putObject("portRange");
                            }
                        }
                    }
                }
            }
            default -> {
                // The XML answer as ec2Result writes it.
            }
        }
        return result;
    }

    /**
     * The Query form {@code p} of {@code action}, one of {@link #XML_STYLE}, as its record writes it:
     * {@code {"<action>Request": ...}} with each member under its Query name, an indexed one
     * ({@code FlowLogId.1}) as {@code {"tag": 1, ...}} and its value as {@code "content"}, two or
     * more of them as a list, and a value that reads as a number or a boolean as one, as DeleteFlowLogs
     * ({@code "FlowLogId": {"content": ..., "tag": 1}}), CreateFlowLogs ({@code "TagSpecification":
     * {"tag": 1, "Tag": {"tag": 1, "Value": true, ...}}}) and ModifySecurityGroupRules
     * ({@code "SecurityGroupRule": {"tag": 1, "SecurityGroupRule": {"IpProtocol": -1, ...}}}) write it.
     */
    private ObjectNode xmlStyleRequest(String action, Map<String, String> p) {
        ObjectNode request = mapper.createObjectNode();
        p.forEach((key, value) -> {
            if (!"Action".equals(key) && !"Version".equals(key)) {
                xmlStyleMember(request, key.split("\\."), 0, value);
            }
        });
        if (request.isEmpty()) {
            return null;
        }
        ObjectNode read = mapper.createObjectNode();
        read.set(action + "Request", request);
        return read;
    }

    private void xmlStyleMember(ObjectNode node, String[] path, int at, String value) {
        String name = path[at];
        if (at + 1 < path.length && INTEGER.matcher(path[at + 1]).matches()) {
            ObjectNode entry = indexedEntry(node, name, Integer.parseInt(path[at + 1]));
            if (at + 2 == path.length) {
                entry.set("content", typed(value));
            } else {
                xmlStyleMember(entry, path, at + 2, value);
            }
        } else if (at + 1 == path.length) {
            node.set(name, typed(value));
        } else {
            JsonNode child = node.get(name);
            xmlStyleMember(child instanceof ObjectNode object ? object : node.putObject(name), path, at + 1, value);
        }
    }

    /** The entry {@code index} of {@code node}'s {@code name}, a list once it holds two. */
    private ObjectNode indexedEntry(ObjectNode node, String name, int index) {
        JsonNode existing = node.get(name);
        if (existing instanceof ArrayNode list) {
            for (JsonNode entry : list) {
                if (entry.path("tag").asInt() == index) {
                    return (ObjectNode) entry;
                }
            }
            return list.addObject().put("tag", index);
        }
        if (existing instanceof ObjectNode entry) {
            if (entry.path("tag").asInt() == index) {
                return entry;
            }
            ArrayNode list = node.putArray(name);
            list.add(entry);
            return list.addObject().put("tag", index);
        }
        return node.putObject(name).put("tag", index);
    }

    /**
     * The answer {@code xml} of {@code action}, one of {@link #XML_STYLE}, as its record writes it:
     * {@code {"<action>Response": {..., "xmlns": ...}}} with each element under its name, an empty
     * one as {@code ""}, a repeated one as a list, and a value that reads as a number or a boolean as
     * one, as DeleteFlowLogs ({@code "unsuccessful": ""}), CreateFlowLogs
     * ({@code "flowLogIdSet": {"item": ...}}) and ModifySecurityGroupRules ({@code "return": true})
     * write it.
     */
    private ObjectNode xmlStyleResult(String action, String xml) {
        XmlParser.XmlElement root = xml == null ? null : XmlParser.extractElementTree(xml, action + "Response");
        if (root == null) {
            return null;
        }
        ObjectNode body = xmlStyleElement(root);
        body.put("xmlns", EC2_NAMESPACE);
        ObjectNode response = mapper.createObjectNode();
        response.set(action + "Response", body);
        return response;
    }

    private ObjectNode xmlStyleElement(XmlParser.XmlElement element) {
        ObjectNode read = mapper.createObjectNode();
        for (XmlParser.XmlElement child : element.children()) {
            JsonNode value = child.children().isEmpty() ? typed(child.text()) : xmlStyleElement(child);
            JsonNode previous = read.get(child.name());
            if (previous instanceof ArrayNode list) {
                list.add(value);
            } else if (previous != null) {
                read.putArray(child.name()).add(previous).add(value);
            } else {
                read.set(child.name(), value);
            }
        }
        return read;
    }

    private JsonNode typed(String value) {
        String trimmed = value == null ? "" : value.trim();
        if (INTEGER.matcher(trimmed).matches()) {
            try {
                return mapper.getNodeFactory().numberNode(Long.parseLong(trimmed));
            } catch (NumberFormatException e) {
                return mapper.getNodeFactory().textNode(value);
            }
        }
        if ("true".equals(trimmed) || "false".equals(trimmed)) {
            return mapper.getNodeFactory().booleanNode(Boolean.parseBoolean(trimmed));
        }
        return mapper.getNodeFactory().textNode(value == null ? "" : value);
    }

    private static void rename(ObjectNode node, String from, String to) {
        JsonNode value = node.remove(from);
        if (value != null) {
            node.set(to, value);
        }
    }

    private static void asText(ObjectNode node, String name) {
        JsonNode value = node.get(name);
        if (value != null && value.isNumber()) {
            node.put(name, value.asText());
        }
    }


    private static boolean hasPrefix(Map<String, String> p, String prefix) {
        for (String key : p.keySet()) {
            if (key.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static void text(ObjectNode node, String name, String value) {
        if (value != null) {
            node.put(name, value);
        }
    }

    private static void number(ObjectNode node, String name, String value) {
        if (value == null) {
            return;
        }
        try {
            node.put(name, Long.parseLong(value.trim()));
        } catch (NumberFormatException e) {
            node.put(name, value);
        }
    }

    private static void bool(ObjectNode node, String name, String value) {
        if (value != null) {
            node.put(name, Boolean.parseBoolean(value.trim()));
        }
    }

    private static Map<String, String> first(MultivaluedMap<String, String> params) {
        Map<String, String> read = new LinkedHashMap<>();
        params.forEach((key, values) -> {
            if (values != null && !values.isEmpty()) {
                read.put(key, values.getFirst());
            }
        });
        return read;
    }

    private static CloudTrailService.ManagementEventInput event(String action, ObjectNode requestParameters,
                                                                String accessKeyId, String region,
                                                                RoutingContext context, ObjectNode result,
                                                                String errorCode, String errorMessage) {
        HttpServerRequest request = context == null ? null : context.request();
        String sourceIp = request == null ? null : RequestSourceAddress.of(request);
        String userAgent = request == null ? null : request.getHeader("User-Agent");
        return new CloudTrailService.ManagementEventInput(EVENT_SOURCE, action, region, accessKeyId,
                requestParameters, result, CloudTrailEventCatalog.of(SERVICE).isReadOnly(action), sourceIp,
                userAgent, null, errorCode, errorMessage);
    }
}
