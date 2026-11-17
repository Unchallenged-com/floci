package io.floci.aws.services.iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.XmlParser;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Reads the {@code <ActionResult>} of a Query protocol answer into the {@code responseElements}
 * CloudTrail records for it, which IAM and STS both write the same way: each member named with a
 * lower first letter, a list's {@code member} elements as an array, a boolean as one, the members
 * a service types as numbers as numbers, a timestamp in the form that service's records use, and
 * no member that carries a secret.
 */
final class QueryResultElements {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern INTEGER = Pattern.compile("-?\\d+");
    private static final Pattern WIRE_TIMESTAMP =
            Pattern.compile("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?Z");

    private final Pattern numbers;
    private final DateTimeFormatter timestamps;
    private final Set<String> secrets;

    /**
     * {@code numbers} matches the names of the members recorded as numbers, {@code timestamps}
     * writes a timestamp, and {@code secrets} names the members left out.
     */
    QueryResultElements(Pattern numbers, DateTimeFormatter timestamps, Set<String> secrets) {
        this.numbers = numbers;
        this.timestamps = timestamps;
        this.secrets = secrets;
    }

    /** The call's {@code <ActionResult>}, or null for a call whose result carries nothing. */
    ObjectNode read(String action, String xml) {
        XmlParser.XmlElement result = XmlParser.extractElementTree(xml, action + "Result");
        if (result == null || result.children().isEmpty()) {
            return null;
        }
        JsonNode read = read(result);
        return read instanceof ObjectNode object && !object.isEmpty() ? object : null;
    }

    static String lowerFirst(String name) {
        return name.isEmpty() ? name : Character.toLowerCase(name.charAt(0)) + name.substring(1);
    }

    private JsonNode read(XmlParser.XmlElement element) {
        if (element.children().isEmpty()) {
            return element.text().isEmpty() ? null : leaf(lowerFirst(element.name()), element.rawText());
        }
        if (element.children().stream().allMatch(child -> "member".equals(child.name()))) {
            ArrayNode members = MAPPER.createArrayNode();
            for (XmlParser.XmlElement child : element.children()) {
                JsonNode value = read(child);
                if (value != null) {
                    members.add(value);
                }
            }
            return members;
        }
        ObjectNode object = MAPPER.createObjectNode();
        for (XmlParser.XmlElement child : element.children()) {
            String name = lowerFirst(child.name());
            JsonNode value = read(child);
            if (value != null && !secrets.contains(name)) {
                object.set(name, value);
            }
        }
        return object;
    }

    private JsonNode leaf(String name, String value) {
        if ("true".equals(value) || "false".equals(value)) {
            return MAPPER.getNodeFactory().booleanNode(Boolean.parseBoolean(value));
        }
        if (numbers.matcher(name).matches() && INTEGER.matcher(value).matches()) {
            return MAPPER.getNodeFactory().numberNode(Long.parseLong(value));
        }
        return MAPPER.getNodeFactory().textNode(timestamp(value));
    }

    private String timestamp(String value) {
        if (!WIRE_TIMESTAMP.matcher(value).matches()) {
            return value;
        }
        try {
            return timestamps.format(Instant.parse(value));
        } catch (DateTimeParseException expected) {
            // Shaped like a timestamp without being one, such as a name a caller chose: kept as sent.
            return value;
        }
    }
}
