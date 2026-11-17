package io.floci.aws.services.s3;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.XmlParser;
import jakarta.ws.rs.core.MultivaluedMap;
import org.jboss.logging.Logger;

import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * The CloudTrail event an S3 request is recorded as, from the operations the S3 User Guide lists
 * (https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html): object-level
 * operations, {@code ListObjectVersions}, {@code DeleteObjects} and {@code HeadBucket} are data events,
 * and bucket-level operations and {@code ListBuckets} management events, under the event names that
 * page gives them, which are not always the API's ({@code PutBucketLifecycleConfiguration} is
 * {@code PutBucketLifecycle}, {@code PutObjectRetention} is {@code PutObjectLockRetention}). The other
 * Object Lock calls are named the same way ({@code GetObjectLockRetention},
 * {@code GetObjectLockLegalHold}, {@code PutObjectLockLegalHold}), as AWS's sample events and its
 * EventBridge schema for S3's CloudTrail events name them. A request that page does not list, such as
 * {@code ListMultipartUploads}, has no event.
 */
public final class S3CloudTrailEvents {

    private static final Logger LOG = Logger.getLogger(S3CloudTrailEvents.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Whether CloudTrail records an event as a data event or a management event. */
    public enum Category { DATA, MANAGEMENT }

    /**
     * One event: its name, its category, and the sub-resource the request named, which CloudTrail
     * carries in {@code requestParameters} as an empty value (null for a request that named none).
     */
    public record Event(String name, Category category, String subresource) {

        /** A read: CloudTrail "considers an action read-only if it does not have any mutating effect". */
        public boolean readOnly() {
            return name.startsWith("Get") || name.startsWith("List") || name.startsWith("Head")
                    || "SelectObjectContent".equals(name);
        }
    }

    /** The data events {@code S3Controller} records itself, on each operation's own success and error paths. */
    static final Set<String> RECORDED_BY_CONTROLLER = Set.of("PutObject", "GetObject", "HeadObject", "DeleteObject",
            "ListObjects", "GetObjectAcl", "PutObjectAnnotation", "GetObjectAnnotation", "ListObjectAnnotations",
            "DeleteObjectAnnotation");

    /** A bucket sub-resource's events for GET, PUT and DELETE, null where the guide lists none. */
    private record BucketEvents(String get, String put, String delete) {
    }

    private static final Map<String, BucketEvents> BUCKET_SUBRESOURCES = Map.ofEntries(
            Map.entry("accelerate", new BucketEvents("GetAccelerateConfiguration", "PutAccelerateConfiguration", null)),
            Map.entry("acl", new BucketEvents("GetBucketAcl", "PutBucketAcl", null)),
            Map.entry("analytics", new BucketEvents("GetBucketAnalyticsConfiguration",
                    "PutBucketAnalyticsConfiguration", "DeleteBucketAnalyticsConfiguration")),
            Map.entry("cors", new BucketEvents("GetBucketCors", "PutBucketCors", "DeleteBucketCors")),
            Map.entry("encryption", new BucketEvents("GetBucketEncryption", "PutBucketEncryption",
                    "DeleteBucketEncryption")),
            Map.entry("intelligent-tiering", new BucketEvents("GetBucketIntelligentTieringConfiguration",
                    "PutBucketIntelligentTieringConfiguration", "DeleteBucketIntelligentTieringConfiguration")),
            Map.entry("inventory", new BucketEvents("GetBucketInventoryConfiguration",
                    "PutBucketInventoryConfiguration", "DeleteBucketInventoryConfiguration")),
            Map.entry("lifecycle", new BucketEvents("GetBucketLifecycle", "PutBucketLifecycle",
                    "DeleteBucketLifecycle")),
            Map.entry("location", new BucketEvents("GetBucketLocation", null, null)),
            Map.entry("logging", new BucketEvents("GetBucketLogging", "PutBucketLogging", null)),
            Map.entry("metrics", new BucketEvents("GetBucketMetricsConfiguration", "PutBucketMetricsConfiguration",
                    "DeleteBucketMetricsConfiguration")),
            Map.entry("notification", new BucketEvents("GetBucketNotification", "PutBucketNotification", null)),
            Map.entry("object-lock", new BucketEvents("GetBucketObjectLockConfiguration",
                    "PutBucketObjectLockConfiguration", null)),
            Map.entry("ownershipControls", new BucketEvents("GetBucketOwnershipControls",
                    "PutBucketOwnershipControls", "DeleteBucketOwnershipControls")),
            Map.entry("policy", new BucketEvents("GetBucketPolicy", "PutBucketPolicy", "DeleteBucketPolicy")),
            Map.entry("policyStatus", new BucketEvents("GetBucketPolicyStatus", null, null)),
            Map.entry("publicAccessBlock", new BucketEvents("GetBucketPublicAccessBlock",
                    "PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock")),
            Map.entry("replication", new BucketEvents("GetBucketReplication", "PutBucketReplication",
                    "DeleteBucketReplication")),
            Map.entry("requestPayment", new BucketEvents("GetBucketRequestPayment", "PutBucketRequestPayment", null)),
            Map.entry("tagging", new BucketEvents("GetBucketTagging", "PutBucketTagging", "DeleteBucketTagging")),
            Map.entry("versioning", new BucketEvents("GetBucketVersioning", "PutBucketVersioning", null)),
            Map.entry("website", new BucketEvents("GetBucketWebsite", "PutBucketWebsite", "DeleteBucketWebsite")));

    /** Configurations listed without an {@code id} and read with one: only the read is a listed event. */
    private static final Set<String> NAMED_CONFIGURATIONS = Set.of("analytics", "intelligent-tiering", "inventory",
            "metrics");

    /** The members S3's configurations type as numbers. */
    private static final Set<String> NUMBER_MEMBERS = Set.of("Days", "Years", "Priority", "NoncurrentDays",
            "NewerNoncurrentVersions", "DaysAfterInitiation", "ObjectSizeGreaterThan", "ObjectSizeLessThan",
            "MaxAgeSeconds", "Minutes");
    /** Members whose text is a caller's own, kept as sent. */
    private static final Set<String> TEXT_MEMBERS = Set.of("Key", "Value", "Prefix", "ID", "Suffix");
    private static final Pattern INTEGER = Pattern.compile("-?\\d+");
    private static final String PRESIGNED_PREFIX = "X-Amz-";

    private S3CloudTrailEvents() {
    }

    /**
     * The event a request is recorded as, or null for one the guide lists no event for.
     *
     * @param bucket          the bucket the request names, null for a request on the service
     * @param key             the object key the request names, null for a request on a bucket
     * @param queryParameters the names of the request's query parameters
     * @param copySource      whether the request carries {@code x-amz-copy-source}
     */
    public static Event of(String method, String bucket, String key, Set<String> queryParameters,
                           boolean copySource) {
        if (method == null) {
            return null;
        }
        if (bucket == null || bucket.isEmpty()) {
            return "GET".equalsIgnoreCase(method) ? new Event("ListBuckets", Category.MANAGEMENT, null) : null;
        }
        String verb = method.toUpperCase(Locale.ROOT);
        return key == null || key.isEmpty()
                ? bucketEvent(verb, queryParameters)
                : objectEvent(verb, queryParameters, copySource);
    }

    private static Event bucketEvent(String method, Set<String> query) {
        switch (method) {
            case "HEAD" -> {
                return new Event("HeadBucket", Category.DATA, null);
            }
            case "POST" -> {
                return query.contains("delete") ? new Event("DeleteObjects", Category.DATA, "delete") : null;
            }
            case "GET" -> {
                if (query.contains("versions")) {
                    return new Event("ListObjectVersions", Category.DATA, "versions");
                }
                if (query.contains("uploads")) {
                    return null;
                }
            }
            default -> {
                // PUT and DELETE are read off the sub-resource below, as GET is.
            }
        }
        for (Map.Entry<String, BucketEvents> subresource : BUCKET_SUBRESOURCES.entrySet()) {
            if (!query.contains(subresource.getKey())) {
                continue;
            }
            if ("GET".equals(method) && NAMED_CONFIGURATIONS.contains(subresource.getKey()) && !query.contains("id")) {
                return null;
            }
            String name = switch (method) {
                case "GET" -> subresource.getValue().get();
                case "PUT" -> subresource.getValue().put();
                case "DELETE" -> subresource.getValue().delete();
                default -> null;
            };
            return name == null ? null : new Event(name, Category.MANAGEMENT, subresource.getKey());
        }
        return switch (method) {
            case "GET" -> new Event("ListObjects", Category.DATA, null);
            case "PUT" -> new Event("CreateBucket", Category.MANAGEMENT, null);
            case "DELETE" -> new Event("DeleteBucket", Category.MANAGEMENT, null);
            default -> null;
        };
    }

    private static Event objectEvent(String method, Set<String> query, boolean copySource) {
        return switch (method) {
            case "GET" -> objectRead(query);
            case "HEAD" -> data("HeadObject", null);
            case "PUT" -> objectWrite(query, copySource);
            case "DELETE" -> {
                if (query.contains("tagging")) {
                    yield data("DeleteObjectTagging", "tagging");
                }
                if (query.contains("annotation")) {
                    yield data("DeleteObjectAnnotation", "annotation");
                }
                yield query.contains("uploadId") ? data("AbortMultipartUpload", null) : data("DeleteObject", null);
            }
            case "POST" -> {
                if (query.contains("uploads")) {
                    yield data("CreateMultipartUpload", "uploads");
                }
                if (query.contains("uploadId")) {
                    yield data("CompleteMultipartUpload", null);
                }
                if (query.contains("restore")) {
                    yield data("RestoreObject", "restore");
                }
                yield query.contains("select") ? data("SelectObjectContent", "select") : null;
            }
            default -> null;
        };
    }

    private static Event objectRead(Set<String> query) {
        for (Map.Entry<String, String> read : List.of(Map.entry("acl", "GetObjectAcl"),
                Map.entry("tagging", "GetObjectTagging"), Map.entry("legal-hold", "GetObjectLockLegalHold"),
                Map.entry("retention", "GetObjectLockRetention"), Map.entry("attributes", "GetObjectAttributes"),
                Map.entry("torrent", "GetObjectTorrent"), Map.entry("annotation", "GetObjectAnnotation"))) {
            if (query.contains(read.getKey())) {
                return data(read.getValue(), read.getKey());
            }
        }
        if (query.contains("annotations")) {
            return data("ListObjectAnnotations", "annotations");
        }
        return query.contains("uploadId") ? data("ListParts", null) : data("GetObject", null);
    }

    private static Event objectWrite(Set<String> query, boolean copySource) {
        for (Map.Entry<String, String> write : List.of(Map.entry("tagging", "PutObjectTagging"),
                Map.entry("retention", "PutObjectLockRetention"), Map.entry("legal-hold", "PutObjectLockLegalHold"),
                Map.entry("acl", "PutObjectAcl"), Map.entry("annotation", "PutObjectAnnotation"))) {
            if (query.contains(write.getKey())) {
                return data(write.getValue(), write.getKey());
            }
        }
        if (query.contains("uploadId") && query.contains("partNumber")) {
            return data(copySource ? "UploadPartCopy" : "UploadPart", null);
        }
        return data(copySource ? "CopyObject" : "PutObject", null);
    }

    private static Event data(String name, String subresource) {
        return new Event(name, Category.DATA, subresource);
    }

    /**
     * A request's query parameters as its record carries them in {@code requestParameters}, a
     * sub-resource with an empty value, without the signature a presigned URL carries in them.
     */
    public static Map<String, String> recordedQueryParameters(MultivaluedMap<String, String> parameters) {
        Map<String, String> query = new TreeMap<>();
        parameters.forEach((name, values) -> {
            if (!name.regionMatches(true, 0, PRESIGNED_PREFIX, 0, PRESIGNED_PREFIX.length())) {
                query.put(name, values.isEmpty() || values.getFirst() == null ? "" : values.getFirst());
            }
        });
        return query;
    }

    /**
     * A bucket policy as CloudTrail writes it in {@code requestParameters}: the document under
     * {@code bucketPolicy}, as JSON. Null for a body that is not a JSON object.
     */
    static ObjectNode policyBody(byte[] body) {
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            JsonNode policy = MAPPER.readTree(body);
            if (!(policy instanceof ObjectNode)) {
                return null;
            }
            ObjectNode parameters = MAPPER.createObjectNode();
            parameters.set("bucketPolicy", policy);
            return parameters;
        } catch (IOException e) {
            LOG.debugv("CloudTrail: bucket policy is not JSON, left out of requestParameters: {0}", e.getMessage());
            return null;
        }
    }

    /**
     * An XML request body as CloudTrail writes one in {@code requestParameters}: the document element
     * under its own name, each child element under its name, a repeated one as an array, and
     * attributes and namespace declarations as members ({@code "xmlns"}), as the guide's
     * {@code PutBucketAcl} record shows
     * (https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-understanding-s3-entries.html).
     * Null for a body that is not XML.
     */
    static ObjectNode xmlBody(byte[] body) {
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            XMLStreamReader reader = XmlParser.newStreamReader(new String(body, StandardCharsets.UTF_8));
            try {
                while (reader.hasNext()) {
                    if (reader.next() == XMLStreamConstants.START_ELEMENT) {
                        ObjectNode document = MAPPER.createObjectNode();
                        String name = reader.getLocalName();
                        document.set(name, readElement(reader));
                        return document;
                    }
                }
                return null;
            } finally {
                reader.close();
            }
        } catch (XMLStreamException e) {
            LOG.debugv("CloudTrail: request body is not XML, left out of requestParameters: {0}", e.getMessage());
            return null;
        }
    }

    private static JsonNode readElement(XMLStreamReader reader) throws XMLStreamException {
        String name = reader.getLocalName();
        ObjectNode element = MAPPER.createObjectNode();
        for (int i = 0; i < reader.getNamespaceCount(); i++) {
            String prefix = reader.getNamespacePrefix(i);
            element.put(prefix == null || prefix.isEmpty() ? "xmlns" : "xmlns:" + prefix, reader.getNamespaceURI(i));
        }
        for (int i = 0; i < reader.getAttributeCount(); i++) {
            String prefix = reader.getAttributePrefix(i);
            String attribute = reader.getAttributeLocalName(i);
            element.put(prefix == null || prefix.isEmpty() ? attribute : prefix + ":" + attribute,
                    reader.getAttributeValue(i));
        }
        StringBuilder text = new StringBuilder();
        boolean children = false;
        while (reader.hasNext()) {
            int event = reader.next();
            if (event == XMLStreamConstants.START_ELEMENT) {
                children = true;
                String childName = reader.getLocalName();
                JsonNode child = readElement(reader);
                JsonNode existing = element.get(childName);
                if (existing == null) {
                    element.set(childName, child);
                } else if (existing instanceof ArrayNode array) {
                    array.add(child);
                } else {
                    ArrayNode array = MAPPER.createArrayNode();
                    array.add(existing);
                    array.add(child);
                    element.set(childName, array);
                }
            } else if (event == XMLStreamConstants.CHARACTERS || event == XMLStreamConstants.CDATA) {
                text.append(reader.getText());
            } else if (event == XMLStreamConstants.END_ELEMENT) {
                break;
            }
        }
        if (!children && element.isEmpty()) {
            return leaf(name, text.toString().trim());
        }
        return element;
    }

    /**
     * A value as S3 types it in a record: a boolean as one, a member S3 models as a number as one,
     * anything else as the text sent. A tag's or a filter's text stays text, whatever it reads as.
     */
    private static JsonNode leaf(String name, String text) {
        if (!TEXT_MEMBERS.contains(name) && ("true".equals(text) || "false".equals(text))) {
            return MAPPER.getNodeFactory().booleanNode(Boolean.parseBoolean(text));
        }
        if (NUMBER_MEMBERS.contains(name) && INTEGER.matcher(text).matches()) {
            return MAPPER.getNodeFactory().numberNode(Long.parseLong(text));
        }
        return MAPPER.getNodeFactory().textNode(text);
    }
}
