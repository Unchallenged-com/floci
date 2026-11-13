package io.floci.aws.services.iam;

import io.floci.aws.testing.RestAssuredJsonUtils;
import io.floci.aws.testing.UnsignedDisabledTestCredentialProfile;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

/**
 * With {@code floci.auth.test-credential-enabled=false} and signatures not verified, IAM enforcement
 * no longer lets {@code test} through without a policy lookup: it refuses it as a key that exists
 * nowhere, as {@code UnknownAccessKeyEnforcementIntegrationTest} pins for any other such key.
 */
@QuarkusTest
@TestProfile(UnsignedDisabledTestCredentialProfile.class)
class UnsignedTestCredentialDisabledIntegrationTest {

    private static final String TEST_KEY_AUTH =
            "AWS4-HMAC-SHA256 Credential=test/20260101/us-east-1/%s/aws4_request, "
                    + "SignedHeaders=host, Signature=not-a-real-signature";

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void aJsonServiceRefusesTheTestCredential() {
        given()
                .header("Authorization", TEST_KEY_AUTH.formatted("lambda"))
                .contentType("application/json")
        .when()
                .get("/2015-03-31/functions")
        .then()
                .statusCode(403)
                .body(containsString("UnrecognizedClientException"));
    }

    @Test
    void s3RefusesTheTestCredentialWithTheS3ErrorCode() {
        given()
                .header("Authorization", TEST_KEY_AUTH.formatted("s3"))
        .when()
                .get("/")
        .then()
                .statusCode(403)
                .body(containsString("InvalidAccessKeyId"));
    }

    @Test
    void anIamManagementCallSignedWithTheTestCredentialIsRefused() {
        given()
                .contentType("application/x-www-form-urlencoded")
                .header("Authorization", TEST_KEY_AUTH.formatted("iam"))
                .formParam("Action", "CreateUser")
                .formParam("UserName", "made-with-the-test-credential")
                .formParam("Version", "2010-05-08")
        .when()
                .post("/")
        .then()
                .statusCode(403)
                .body(containsString("<Code>InvalidClientTokenId</Code>"));
    }
}
