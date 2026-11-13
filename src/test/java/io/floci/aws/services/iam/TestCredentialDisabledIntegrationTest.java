package io.floci.aws.services.iam;

import io.floci.aws.testing.DisabledTestCredentialProfile;
import io.floci.aws.testing.RestAssuredJsonUtils;
import io.floci.aws.testutil.AwsRequestSigner;
import io.floci.aws.testutil.S3RequestSigner;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import io.restassured.path.xml.XmlPath;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * With {@code floci.auth.test-credential-enabled=false}, {@code test} / {@code test} is a key Floci
 * does not know: every verifier answers it as it answers any access key that exists nowhere, while
 * the seeded deployer principal still provisions the account.
 */
@QuarkusTest
@TestProfile(DisabledTestCredentialProfile.class)
class TestCredentialDisabledIntegrationTest {

    private static final String JSON_1_0 = "application/x-amz-json-1.0";
    private static final String FORM = "application/x-www-form-urlencoded";
    private static final String UNKNOWN_KEY = "AKIAUNKNOWNACCESSKEY";

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void aJsonServiceRefusesTheTestCredentialAsAnUnknownKey() {
        for (String accessKeyId : new String[] {"test", UNKNOWN_KEY}) {
            given()
                .filter(AwsRequestSigner.signedAs(accessKeyId, "test", "sqs"))
                .contentType(JSON_1_0)
                .header("X-Amz-Target", "AmazonSQS.ListQueues")
                .body("{}")
            .when()
                .post("/")
            .then()
                .statusCode(403)
                .body("__type", equalTo("UnrecognizedClientException"));
        }
    }

    @Test
    void getCallerIdentityRefusesTheTestCredentialAsAnUnknownKey() {
        for (String accessKeyId : new String[] {"test", UNKNOWN_KEY}) {
            given()
                .filter(AwsRequestSigner.signedAs(accessKeyId, "test", "sts"))
                .contentType(FORM)
                .body("Action=GetCallerIdentity&Version=2011-06-15")
            .when()
                .post("/")
            .then()
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("InvalidClientTokenId"));
        }
    }

    @Test
    void s3RefusesAHeaderSignedWithTheTestCredentialAsAnUnknownKey() {
        for (String accessKeyId : new String[] {"test", UNKNOWN_KEY}) {
            given()
                .filter(S3RequestSigner.signedAs(accessKeyId, "test"))
            .when()
                .get("/")
            .then()
                .statusCode(403)
                .body("Error.Code", equalTo("InvalidAccessKeyId"));
        }
    }

    @Test
    void s3RefusesAUrlPresignedWithTheTestCredentialAsAnUnknownKey() throws Exception {
        URI object = URI.create("http://localhost:" + RestAssured.port + "/test-credential-bucket/object.txt");
        String unknownKeyAnswer = presignedGet(UNKNOWN_KEY, object);

        assertEquals(unknownKeyAnswer, presignedGet("test", object));
    }

    @Test
    void theSeededDeployerProvisionsAUserWhoseKeyIsAccepted() throws Exception {
        URI endpoint = URI.create("http://localhost:" + RestAssured.port + "/");
        String userName = "provisioned-" + UUID.randomUUID().toString().substring(0, 8);
        AwsRequestSigner deployer = AwsRequestSigner.signedAs("floci", "floci", "iam");

        query(endpoint, deployer, "CreateUser", Map.of("UserName", userName)).then().statusCode(200);
        XmlPath key = query(endpoint, deployer, "CreateAccessKey", Map.of("UserName", userName))
                .then().statusCode(200).extract().xmlPath();
        String accessKeyId = key.getString("CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.AccessKeyId");
        String secretAccessKey =
                key.getString("CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.SecretAccessKey");

        given()
            .filter(AwsRequestSigner.signedAs(accessKeyId, secretAccessKey, "sts"))
            .contentType(FORM)
            .body("Action=GetCallerIdentity&Version=2011-06-15")
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("GetCallerIdentityResponse.GetCallerIdentityResult.Arn", endsWith(":user/" + userName));
    }

    /** The error code S3 answers a presigned GET with, signed with {@code accessKeyId} and secret {@code test}. */
    private static String presignedGet(String accessKeyId, URI object) throws Exception {
        String query = S3RequestSigner.signedAs(accessKeyId, "test").presignedQuery("GET", object, 300);
        Response response = given().urlEncodingEnabled(false).when().get(object + "?" + query);
        assertEquals(403, response.statusCode(), response.asString());
        return response.xmlPath().getString("Error.Code");
    }

    private static Response query(URI endpoint, AwsRequestSigner signer, String action, Map<String, String> parameters)
            throws Exception {
        String body = "Action=" + action + "&Version=2010-05-08&" + parameters.entrySet().stream()
                .map(entry -> URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        return given().headers(signer.headersFor("POST", endpoint, Map.of(), body.getBytes(StandardCharsets.UTF_8)))
                .contentType(FORM).body(body).post(endpoint);
    }
}
