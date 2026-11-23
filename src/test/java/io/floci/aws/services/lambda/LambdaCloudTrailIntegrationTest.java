package io.floci.aws.services.lambda;

import com.fasterxml.jackson.databind.JsonNode;
import io.floci.aws.core.common.AwsArnUtils;
import io.floci.aws.core.common.AwsRegions;
import io.floci.aws.services.cloudtrail.CloudTrailLogWriter;
import io.floci.aws.testing.AwsTestClients;
import io.floci.aws.testing.CloudTrailLogFiles;
import io.floci.aws.testing.CloudTrailRequests;
import io.floci.aws.testing.EnforcementFixtures;
import io.floci.aws.testing.EnforcementFixtures.UserCredentials;
import io.floci.aws.testing.IamEnforcementProfile;
import io.floci.aws.testing.LambdaCodeFixtures;
import io.floci.aws.testing.PartitionCleanup;
import io.floci.aws.testing.RestAssuredJsonUtils;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.FunctionUrlAuthType;
import software.amazon.awssdk.services.lambda.model.LambdaException;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.floci.aws.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The Lambda management calls Floci records reach a trail's log files under the event names Lambda's records
 * give them, with their path, query and body members, and without the code and the environment variables.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class LambdaCloudTrailIntegrationTest {

    private static final Region REGION = Region.US_EAST_1;
    private static final String SECRET = "do-not-log-" + UUID.randomUUID();

    @TestHTTPResource("/")
    static URI baseUri;

    @Inject
    CloudTrailLogWriter writer;

    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void managementCallsAreRecordedUnderTheirEventNames() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-lambda-logs-" + suffix;
        startTrail(account, "ct-lambda-" + suffix, logs);
        String name = "ct-fn-" + suffix;
        byte[] archive = LambdaCodeFixtures.nodeJsZip("exports.handler = async () => 'ok';");
        String role = AwsArnUtils.Arn.global(AwsRegions.partitionFor(REGION.id()), "iam", account, "role/ct")
                .toString();

        try (LambdaClient lambda = AwsTestClients.create(LambdaClient.builder(), account, REGION, baseUri)) {
            String arn = lambda.createFunction(request -> request.functionName(name).runtime("nodejs22.x")
                    .handler("index.handler").role(role).environment(env -> env.variables(Map.of("TOKEN", SECRET)))
                    .code(code -> code.zipFile(SdkBytes.fromByteArray(archive)))).functionArn();
            lambda.getFunction(request -> request.functionName(name));
            lambda.listFunctions();
            lambda.updateFunctionCode(request -> request.functionName(name).publish(true)
                    .zipFile(SdkBytes.fromByteArray(archive)));
            lambda.updateFunctionConfiguration(request -> request.functionName(name).timeout(10));
            lambda.addPermission(request -> request.functionName(name).statementId("open")
                    .action("lambda:InvokeFunction").principal("*"));
            lambda.removePermission(request -> request.functionName(name).statementId("open"));
            lambda.createFunctionUrlConfig(request -> request.functionName(name).authType(FunctionUrlAuthType.NONE));
            lambda.listVersionsByFunction(request -> request.functionName(name).maxItems(50));
            lambda.listAliases(request -> request.functionName(name));
            lambda.listTags(request -> request.resource(arn));
            lambda.getAccountSettings();
            lambda.listLayers();
            lambda.getFunctionCodeSigningConfig(request -> request.functionName(name));
            lambda.putFunctionEventInvokeConfig(request -> request.functionName(name).maximumRetryAttempts(1));
            lambda.getFunctionEventInvokeConfig(request -> request.functionName(name));
            String mapping = UUID.randomUUID().toString();
            assertThrows(LambdaException.class, () -> lambda.getEventSourceMapping(request -> request.uuid(mapping)));
            assertThrows(LambdaException.class, () -> lambda.getFunction(request -> request.functionName(name + "-x")));
            lambda.publishLayerVersion(request -> request.layerName("ct-layer-" + suffix)
                    .compatibleRuntimesWithStrings("nodejs22.x")
                    .content(content -> content.zipFile(SdkBytes.fromByteArray(archive))));
            lambda.deleteFunction(request -> request.functionName(name));

            List<JsonNode> records = lambdaRecords(account, logs);
            assertThat(records.toString(), not(containsString(SECRET)));

            JsonNode create = only(records, "CreateFunction20150331");
            assertThat(create.path("eventSource").asText(), equalTo("lambda.amazonaws.com"));
            assertThat(create.path("readOnly").asBoolean(true), equalTo(false));
            assertThat(create.path("requestParameters").path("functionName").asText(), equalTo(name));
            assertThat(create.path("requestParameters").path("runtime").asText(), equalTo("nodejs22.x"));
            assertThat(isEmptyObject(create.path("requestParameters").path("code")), equalTo(true));
            assertThat(isEmptyObject(create.path("requestParameters").path("environment")), equalTo(true));
            assertThat(create.path("responseElements").path("functionArn").asText(), equalTo(arn));
            assertThat(isEmptyObject(create.path("responseElements").path("environment")), equalTo(true));

            JsonNode get = only(records, "GetFunction20150331v2");
            assertThat(get.path("readOnly").asBoolean(), equalTo(true));
            assertThat(get.path("requestParameters").path("functionName").asText(), equalTo(name));
            assertThat(get.path("responseElements").isNull(), equalTo(true));
            assertThat(only(records, "ListFunctions20150331").path("readOnly").asBoolean(), equalTo(true));

            JsonNode code = only(records, "UpdateFunctionCode20150331v2").path("requestParameters");
            assertThat(code.path("functionName").asText(), equalTo(arn));
            assertThat(code.path("fullyQualifiedArn").path("relativeId").path("functionName").asText(),
                    equalTo(name));
            assertThat(code.path("fullyQualifiedArn").path("arnPrefix").path("account").asText(), equalTo(account));
            assertThat(isEmptyObject(code.path("fullyQualifiedArn").path("functionQualifier")), equalTo(true));
            assertThat(code.path("publish").asBoolean(), equalTo(true));
            assertThat(code.path("dryRun").isBoolean() && !code.path("dryRun").asBoolean(), equalTo(true));
            assertThat(code.has("zipFile"), equalTo(false));

            JsonNode configuration = only(records, "UpdateFunctionConfiguration20150331v2");
            assertThat(configuration.path("requestParameters").path("timeout").asInt(), equalTo(10));
            assertThat(isEmptyObject(configuration.path("requestParameters").path("environment")), equalTo(true));
            assertThat(configuration.path("responseElements").path("timeout").asInt(), equalTo(10));

            JsonNode permission = only(records, "AddPermission20150331v2");
            assertThat(permission.path("requestParameters").path("principal").asText(), equalTo("*"));
            assertThat(permission.path("responseElements").path("statement").asText(), containsString("\"open\""));
            JsonNode removed = only(records, "RemovePermission20150331v2");
            assertThat(removed.path("requestParameters").path("statementId").asText(), equalTo("open"));
            assertThat(removed.path("responseElements").isNull(), equalTo(true));

            JsonNode url = only(records, "CreateFunctionUrlConfig");
            assertThat(url.path("requestParameters").path("authType").asText(), equalTo("NONE"));
            assertThat(url.path("responseElements").path("functionUrl").asText(null), notNullValue());

            JsonNode missing = records.stream().filter(record -> "GetFunction20150331v2".equals(
                    record.path("eventName").asText()) && record.has("errorCode")).findFirst().orElseThrow();
            assertThat(missing.path("errorCode").asText(), equalTo("ResourceNotFoundException"));
            assertThat(missing.path("requestParameters").path("functionName").asText(), equalTo(name + "-x"));

            JsonNode layer = only(records, "PublishLayerVersion20181031");
            assertThat(isEmptyObject(layer.path("requestParameters").path("content")), equalTo(true));
            assertThat(layer.path("additionalEventData").path("signatureStatus").asText(), equalTo("VALID"));
            assertThat(layer.path("responseElements").path("version").isNumber(), equalTo(true));

            JsonNode delete = only(records, "DeleteFunction20150331");
            assertThat(delete.path("requestParameters").path("functionName").asText(), equalTo(name));
            assertThat(delete.path("responseElements").isNull(), equalTo(true));

            JsonNode versions = only(records, "ListVersionsByFunction20150331");
            assertThat(versions.path("readOnly").asBoolean(), equalTo(true));
            assertThat(versions.path("requestParameters").path("maxItems").asInt(), equalTo(50));
            assertThat(only(records, "ListAliases20150331").path("requestParameters").path("functionName").asText(),
                    equalTo(name));
            assertThat(only(records, "ListTags20170331").path("requestParameters").path("resource").asText(),
                    equalTo(arn));
            assertThat(only(records, "GetAccountSettings20160819").path("readOnly").asBoolean(), equalTo(true));
            assertThat(only(records, "ListLayers20181031").path("readOnly").asBoolean(), equalTo(true));
            assertThat(only(records, "GetFunctionCodeSigningConfig").path("requestParameters").path("functionName")
                    .asText(), equalTo(name));
            assertThat(only(records, "PutFunctionEventInvokeConfig").path("requestParameters")
                    .path("maximumRetryAttempts").asInt(), equalTo(1));
            assertThat(only(records, "GetFunctionEventInvokeConfig").path("responseElements").isNull(),
                    equalTo(true));
            JsonNode esm = only(records, "GetEventSourceMapping20150331");
            assertThat(esm.path("errorCode").asText(null), notNullValue());
            assertThat(esm.path("requestParameters").path("uUID").asText(), equalTo(mapping));
        }
    }

    @Test
    void aRefusedCallIsRecordedWithoutItsMembers() throws IOException {
        String account = account();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String logs = "ct-lambda-logs-" + suffix;
        startTrail(account, "ct-lambda-" + suffix, logs);
        String user = "ct-user-" + suffix;
        UserCredentials credentials = EnforcementFixtures.createUser(cleanup, baseUri.getPort(),
                auth(account, "iam"), user);

        try (LambdaClient lambda = AwsTestClients.create(LambdaClient.builder(), credentials.accessKeyId(),
                credentials.secretAccessKey(), REGION, baseUri)) {
            LambdaException error = assertThrows(LambdaException.class, () -> lambda.addPermission(request -> request
                    .functionName("ct-fn-" + suffix).statementId("open").action("lambda:InvokeFunction")
                    .principal("*")));
            assertThat(error.statusCode(), equalTo(403));
        }

        JsonNode refused = only(lambdaRecords(account, logs), "AddPermission20150331v2");
        assertThat(refused.path("errorCode").asText(), equalTo("AccessDenied"));
        assertThat(refused.path("errorMessage").asText(), containsString("lambda:AddPermission"));
        assertThat(refused.path("userIdentity").path("userName").asText(), equalTo(user));
        assertThat(refused.path("requestParameters").isNull(), equalTo(true));
        assertThat(refused.path("responseElements").isNull(), equalTo(true));
    }

    private static boolean isEmptyObject(JsonNode node) {
        return node.isObject() && node.isEmpty();
    }

    private static String account() {
        return "6614" + String.format("%08d", (int) (Math.random() * 100_000_000));
    }

    private void startTrail(String account, String trail, String bucket) {
        given().port(baseUri.getPort()).header("Authorization", auth(account, "s3"))
                .when().put("/" + bucket).then().statusCode(200);
        cleanup.register(() -> EnforcementFixtures.removeBucket(baseUri.getPort(), auth(account, "s3"), bucket));
        cloudTrail(account, "CreateTrail", "{\"Name\":\"" + trail + "\",\"S3BucketName\":\"" + bucket + "\"}");
        cleanup.register(() -> cloudTrail(account, "DeleteTrail", "{\"Name\":\"" + trail + "\"}"));
        cloudTrail(account, "StartLogging", "{\"Name\":\"" + trail + "\"}");
    }

    private static void cloudTrail(String account, String action, String body) {
        CloudTrailRequests.invokeCloudTrail(auth(account, "cloudtrail"), action, body).then().statusCode(200);
    }

    /** The Lambda records of {@code account}, read from the log files delivered to {@code bucket}. */
    private List<JsonNode> lambdaRecords(String account, String bucket) throws IOException {
        writer.flushNow();
        return CloudTrailLogFiles.records(bucket, auth(account, "s3")).stream()
                .filter(record -> "lambda.amazonaws.com".equals(record.path("eventSource").asText()))
                .toList();
    }

    private static JsonNode only(List<JsonNode> records, String eventName) {
        List<JsonNode> found = records.stream()
                .filter(record -> eventName.equals(record.path("eventName").asText()) && !record.has("errorCode"))
                .toList();
        if (found.isEmpty()) {
            found = records.stream().filter(record -> eventName.equals(record.path("eventName").asText())).toList();
        }
        assertThat(eventName + " in " + records, found, hasSize(1));
        return found.getFirst();
    }
}
