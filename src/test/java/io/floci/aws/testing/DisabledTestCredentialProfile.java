package io.floci.aws.testing;

import io.quarkus.test.junit.QuarkusTestProfile;

import java.util.Map;

/**
 * The {@code test} credential turned off, with signature validation, IAM enforcement and S3 auth
 * enforcement on, and the deployer principal seeded so a class can still provision. Quarkus builds
 * the application once per distinct profile class, so the classes that need this combination share
 * this one.
 *
 * <p>The overrides, and who relies on them:
 * <ul>
 *   <li>{@code floci.auth.test-credential-enabled=false} makes {@code test} a key Floci does not
 *   know. Every class here relies on it.</li>
 *   <li>{@code floci.auth.validate-signatures=true}, {@code floci.services.iam.enforcement-enabled=true}
 *   and {@code floci.services.s3.enforce-auth=true} put every verifier the credential used to pass
 *   in the request's way.</li>
 *   <li>{@code floci.services.iam.seed-deployer-principal=true} gives the classes a credential to
 *   provision with once {@code test} is refused.</li>
 * </ul>
 */
public class DisabledTestCredentialProfile implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.of(
                "floci.auth.test-credential-enabled", "false",
                "floci.auth.validate-signatures", "true",
                "floci.services.iam.enforcement-enabled", "true",
                "floci.services.s3.enforce-auth", "true",
                "floci.services.iam.seed-deployer-principal", "true");
    }
}
