package io.floci.aws.services.ec2;

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
import java.util.function.Supplier;

/**
 * Records EC2 calls as CloudTrail management events. "All Amazon EC2 API actions are logged as
 * management events" (https://docs.aws.amazon.com/AWSEC2/latest/APIReference/using-cloudtrail.html),
 * but an EC2 record writes a call's members in EC2's own schema, not botocore's: a list of instances
 * is {@code "instancesSet": {"items": [{"instanceId": ...}]}}, an empty list {@code {}}. No published
 * source carries that schema any more, so Floci records only the calls whose record a capture from
 * 2024 or later shows, each mapped from its Query form in {@link #requestParameters}, and listed in
 * the vendored {@code aws/ec2-cloudtrail-events.json} ({@link CloudTrailEventCatalog}), which also
 * says which are read-only (the Service Reference's access level).
 *
 * <p>{@code responseElements} is the call's XML answer as {@link CloudTrailShapes#ec2Result} writes
 * it, null for a read-only call and a failed one. A failed call is recorded under its EC2 code
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
                result = "DeleteFlowLogs".equals(action) ? deleteFlowLogsResult(xml)
                        : CloudTrailShapes.of(SERVICE).ec2Result(action, xml);
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
            // 2024-10-30.
            case "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress" -> {
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
            // DeleteFlowLogs, 2024-10-08 and 2024-07-31: the request as its own XML.
            case "DeleteFlowLogs" -> {
                ObjectNode request = read.putObject("DeleteFlowLogsRequest");
                if (p.containsKey("FlowLogId.1") && !p.containsKey("FlowLogId.2")) {
                    request.putObject("FlowLogId").put("content", p.get("FlowLogId.1")).put("tag", 1);
                } else {
                    ArrayNode ids = request.putArray("FlowLogId");
                    for (int i = 1; p.containsKey("FlowLogId." + i); i++) {
                        ids.addObject().put("content", p.get("FlowLogId." + i)).put("tag", i);
                    }
                }
            }
            // GetPasswordData, 2024-10-11 and 2024-07-30.
            case "GetPasswordData" -> text(read, "instanceId", p.get("InstanceId"));
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
     * DeleteFlowLogs's answer as its record writes it, 2024-10-08 and 2024-07-31:
     * {@code {"DeleteFlowLogsResponse": {"requestId", "unsuccessful": "", "xmlns"}}}.
     */
    private ObjectNode deleteFlowLogsResult(String xml) {
        XmlParser.XmlElement root = xml == null ? null : XmlParser.extractElementTree(xml, "DeleteFlowLogsResponse");
        if (root == null) {
            return null;
        }
        ObjectNode response = mapper.createObjectNode();
        ObjectNode body = response.putObject("DeleteFlowLogsResponse");
        XmlParser.XmlElement requestId = root.child("requestId");
        text(body, "requestId", requestId == null ? null : requestId.text());
        XmlParser.XmlElement unsuccessful = root.child("unsuccessful");
        if (unsuccessful == null || unsuccessful.children().isEmpty()) {
            body.put("unsuccessful", "");
        }
        body.put("xmlns", EC2_NAMESPACE);
        return response;
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
