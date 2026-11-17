package io.floci.aws.services.s3;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;

class S3CloudTrailEventsTest {

    private static Set<String> query(String names) {
        return names.isEmpty() ? Set.of() : Arrays.stream(names.split("&")).collect(Collectors.toSet());
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "GET||||ListBuckets|MANAGEMENT",
        "PUT|b|||CreateBucket|MANAGEMENT",
        "DELETE|b|||DeleteBucket|MANAGEMENT",
        "HEAD|b|||HeadBucket|DATA",
        "PUT|b||lifecycle|PutBucketLifecycle|MANAGEMENT",
        "GET|b||lifecycle|GetBucketLifecycle|MANAGEMENT",
        "PUT|b||object-lock|PutBucketObjectLockConfiguration|MANAGEMENT",
        "PUT|b||publicAccessBlock|PutBucketPublicAccessBlock|MANAGEMENT",
        "PUT|b||accelerate|PutAccelerateConfiguration|MANAGEMENT",
        "GET|b||metrics&id|GetBucketMetricsConfiguration|MANAGEMENT",
        "GET|b||versions|ListObjectVersions|DATA",
        "GET|b||list-type|ListObjects|DATA",
        "POST|b||delete|DeleteObjects|DATA",
        "PUT|b|k|retention|PutObjectLockRetention|DATA",
        "PUT|b|k|legal-hold|PutObjectLockLegalHold|DATA",
        "GET|b|k|legal-hold|GetObjectLockLegalHold|DATA",
        "GET|b|k|retention|GetObjectLockRetention|DATA",
        "PUT|b|k|partNumber&uploadId|UploadPart|DATA",
        "POST|b|k|uploads|CreateMultipartUpload|DATA",
        "POST|b|k|uploadId|CompleteMultipartUpload|DATA",
        "DELETE|b|k|uploadId|AbortMultipartUpload|DATA",
        "GET|b|k|uploadId|ListParts|DATA",
        "GET|b|k|attributes|GetObjectAttributes|DATA",
        "DELETE|b|k|tagging|DeleteObjectTagging|DATA",
        "PUT|b|k||PutObject|DATA"})
    void eventsAreNamedAsTheS3UserGuideNamesThem(String method, String bucket, String key, String query,
                                                  String name, S3CloudTrailEvents.Category category) {
        S3CloudTrailEvents.Event event = S3CloudTrailEvents.of(method, bucket, key, query(query == null ? "" : query),
                false);
        assertThat(event.name(), equalTo(name));
        assertThat(event.category(), equalTo(category));
    }

    @Test
    void aCopyIsCopyObjectAndAPartCopyUploadPartCopy() {
        assertThat(S3CloudTrailEvents.of("PUT", "b", "k", Set.of(), true).name(), equalTo("CopyObject"));
        assertThat(S3CloudTrailEvents.of("PUT", "b", "k", Set.of("partNumber", "uploadId"), true).name(),
                equalTo("UploadPartCopy"));
    }

    @Test
    void requestsTheGuideListsNoEventForHaveNone() {
        assertThat(S3CloudTrailEvents.of("GET", "b", null, Set.of("uploads"), false), nullValue());
        assertThat(S3CloudTrailEvents.of("GET", "b", null, Set.of("metrics"), false), nullValue());
        assertThat(S3CloudTrailEvents.of("PUT", "b", null, Set.of("location"), false), nullValue());
    }

    @Test
    void anXmlBodysBooleansAndModeledNumbersAreTypedAndATagStaysText() {
        ObjectNode body = S3CloudTrailEvents.xmlBody(("""
                <LifecycleConfiguration><Rule><ID>7</ID><Filter><Prefix>1</Prefix></Filter><Status>Enabled</Status>
                  <Expiration><Days>1</Days><ExpiredObjectDeleteMarker>false</ExpiredObjectDeleteMarker></Expiration>
                  <Tag><Key>true</Key><Value>2</Value></Tag>
                </Rule></LifecycleConfiguration>""").getBytes(StandardCharsets.UTF_8));
        ObjectNode rule = (ObjectNode) body.path("LifecycleConfiguration").path("Rule");
        assertThat(rule.path("Expiration").path("Days").isNumber(), equalTo(true));
        assertThat(rule.path("Expiration").path("ExpiredObjectDeleteMarker").isBoolean(), equalTo(true));
        assertThat(rule.path("ID").isTextual(), equalTo(true));
        assertThat(rule.path("Filter").path("Prefix").isTextual(), equalTo(true));
        assertThat(rule.path("Tag").path("Key").isTextual(), equalTo(true));
        assertThat(rule.path("Tag").path("Value").isTextual(), equalTo(true));
    }

    @Test
    void aBucketPolicyIsRecordedAsItsDocument() {
        ObjectNode body = S3CloudTrailEvents.policyBody(
                "{\"Version\":\"2012-10-17\",\"Statement\":[]}".getBytes(StandardCharsets.UTF_8));
        assertThat(body.path("bucketPolicy").path("Version").asText(), equalTo("2012-10-17"));
        assertThat(S3CloudTrailEvents.policyBody("not json".getBytes(StandardCharsets.UTF_8)), nullValue());
    }

    @Test
    void anXmlBodyIsWrittenAsTheGuidesPutBucketAclRecordWritesOne() {
        ObjectNode body = S3CloudTrailEvents.xmlBody(("""
                <AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                  <Owner><ID>owner-id</ID></Owner>
                  <AccessControlList><Grant>
                    <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
                      <ID>owner-id</ID></Grantee>
                    <Permission>FULL_CONTROL</Permission>
                  </Grant></AccessControlList>
                </AccessControlPolicy>""").getBytes(StandardCharsets.UTF_8));
        ObjectNode policy = (ObjectNode) body.path("AccessControlPolicy");
        assertThat(policy.path("xmlns").asText(), equalTo("http://s3.amazonaws.com/doc/2006-03-01/"));
        assertThat(policy.path("Owner").path("ID").asText(), equalTo("owner-id"));
        assertThat(policy.path("AccessControlList").path("Grant").path("Grantee").path("xsi:type").asText(),
                equalTo("CanonicalUser"));
        assertThat(policy.path("AccessControlList").path("Grant").path("Permission").asText(),
                equalTo("FULL_CONTROL"));
        assertThat(S3CloudTrailEvents.xmlBody("{\"Version\":\"2012-10-17\"}".getBytes(StandardCharsets.UTF_8)),
                nullValue());
    }
}
