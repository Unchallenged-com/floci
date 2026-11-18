package io.floci.aws.services.iam;

import io.floci.aws.core.common.XmlParser;
import io.floci.aws.testing.IamEnforcementProfile;
import io.floci.aws.testing.SamlMetadata;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.response.ValidatableResponse;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.equalTo;

/**
 * Under IAM enforcement, {@code AssumeRoleWithSAML} refuses an assertion without the
 * {@code https://aws.amazon.com/SAML/Attributes/RoleSessionName} attribute as AWS does: "Error: RoleSessionName is
 * required in AuthnResponse (service: AWSSecurityTokenService; status code: 400; error code: InvalidIdentityToken)".
 * Without enforcement such an assertion is still accepted, which {@link AssumeRoleWithSamlValidationIntegrationTest}
 * covers.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class AssumeRoleWithSamlSessionNameEnforcementIntegrationTest {
    private static final String ACCOUNT = "000000000000";
    private static final String ISSUER = "https://idp.example.test/session-name";
    private static final String SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";

    private static KeyPair signingKeys;
    private static String certificateBase64;

    @BeforeAll
    static void createSigningCertificate() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        signingKeys = generator.generateKeyPair();
        Instant now = Instant.now();
        X500Name name = new X500Name("CN=Floci SAML session name test provider");
        X509CertificateHolder holder = new JcaX509v3CertificateBuilder(
                name, BigInteger.ONE, Date.from(now.minusSeconds(60)), Date.from(now.plusSeconds(3600)),
                name, signingKeys.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(signingKeys.getPrivate()));
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
        certificateBase64 = Base64.getEncoder().encodeToString(certificate.getEncoded());
    }

    @Test
    void anAssertionWithoutASessionNameIsRefused() {
        String suffix = suffix();
        String provider = createProvider(suffix);
        String role = createRole(suffix, provider);
        assume(role, provider, signedAssertion(role, provider, null))
                .statusCode(400)
                .body("ErrorResponse.Error.Code", equalTo("InvalidIdentityToken"))
                .body("ErrorResponse.Error.Message", equalTo("RoleSessionName is required in AuthnResponse"));
    }

    @Test
    void anAssertionNamingItsSessionIsAccepted() {
        String suffix = suffix();
        String provider = createProvider(suffix);
        String role = createRole(suffix, provider);
        assume(role, provider, signedAssertion(role, provider, "alice@example.test"))
                .statusCode(200)
                .body("AssumeRoleWithSAMLResponse.AssumeRoleWithSAMLResult.AssumedRoleUser.Arn",
                        endsWith("/alice@example.test"));
    }

    private static ValidatableResponse assume(String role, String provider, String assertion) {
        return given().contentType("application/x-www-form-urlencoded")
                .formParam("Action", "AssumeRoleWithSAML")
                .formParam("RoleArn", role)
                .formParam("PrincipalArn", provider)
                .formParam("SAMLAssertion", assertion)
                .when().post("/").then();
    }

    private static String createProvider(String suffix) {
        return given().contentType("application/x-www-form-urlencoded")
                .formParam("Action", "CreateSAMLProvider").formParam("Name", "session-name-" + suffix)
                .formParam("SAMLMetadataDocument", SamlMetadata.forEntity(ISSUER, certificateBase64))
                .header("Authorization", auth()).when().post("/").then().statusCode(200)
                .extract().path("CreateSAMLProviderResponse.CreateSAMLProviderResult.SAMLProviderArn");
    }

    private static String createRole(String suffix, String provider) {
        String name = "saml-session-name-" + suffix;
        String trust = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Federated\":\""
                + provider + "\"},\"Action\":\"sts:AssumeRoleWithSAML\"}]}";
        given().contentType("application/x-www-form-urlencoded")
                .formParam("Action", "CreateRole").formParam("RoleName", name)
                .formParam("AssumeRolePolicyDocument", trust)
                .header("Authorization", auth()).when().post("/").then().statusCode(200);
        return "arn:aws:iam::" + ACCOUNT + ":role/" + name;
    }

    private static String auth() {
        return "AWS4-HMAC-SHA256 Credential=" + ACCOUNT + "/20260907/us-east-1/iam/aws4_request, "
                + "SignedHeaders=host, Signature=test";
    }

    private static String suffix() {
        return UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    }

    /** A signed assertion for {@code role}, carrying a RoleSessionName attribute unless {@code sessionName} is null. */
    private static String signedAssertion(String role, String provider, String sessionName) {
        Instant expiry = Instant.now().plusSeconds(300);
        String sessionAttribute = sessionName == null ? ""
                : "<saml:Attribute Name=\"https://aws.amazon.com/SAML/Attributes/RoleSessionName\"><saml:AttributeValue>"
                        + sessionName + "</saml:AttributeValue></saml:Attribute>";
        String id = "_" + UUID.randomUUID();
        String xml = "<saml:Assertion xmlns:saml=\"" + SAML_NS + "\" ID=\"" + id + "\" Version=\"2.0\" IssueInstant=\""
                + Instant.now() + "\"><saml:Issuer>" + ISSUER + "</saml:Issuer><saml:Subject>"
                + "<saml:NameID Format=\"persistent\">saml-subject</saml:NameID>"
                + "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"
                + "<saml:SubjectConfirmationData Recipient=\"https://signin.aws.amazon.com/saml\" NotOnOrAfter=\""
                + expiry + "\"/></saml:SubjectConfirmation></saml:Subject>"
                + "<saml:Conditions NotBefore=\"" + Instant.now().minusSeconds(30) + "\" NotOnOrAfter=\"" + expiry
                + "\"><saml:AudienceRestriction><saml:Audience>urn:amazon:webservices</saml:Audience>"
                + "</saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement>"
                + "<saml:Attribute Name=\"https://aws.amazon.com/SAML/Attributes/Role\"><saml:AttributeValue>"
                + role + "," + provider + "</saml:AttributeValue></saml:Attribute>" + sessionAttribute
                + "</saml:AttributeStatement></saml:Assertion>";
        try {
            Document document = XmlParser.parseDocument(xml);
            Element assertion = document.getDocumentElement();
            assertion.setIdAttribute("ID", true);
            XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
            Reference reference = factory.newReference("#" + id,
                    factory.newDigestMethod(DigestMethod.SHA256, null),
                    List.of(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)), null, null);
            SignedInfo signedInfo = factory.newSignedInfo(
                    factory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                    factory.newSignatureMethod(SignatureMethod.RSA_SHA256, null), List.of(reference));
            factory.newXMLSignature(signedInfo, null).sign(new DOMSignContext(signingKeys.getPrivate(), assertion));
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            StringWriter output = new StringWriter();
            transformer.transform(new DOMSource(document), new StreamResult(output));
            return Base64.getEncoder().encodeToString(output.toString().getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
