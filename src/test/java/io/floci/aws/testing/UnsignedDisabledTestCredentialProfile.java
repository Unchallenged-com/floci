package io.floci.aws.testing;

import io.quarkus.test.junit.QuarkusTestProfile;

import java.util.Map;

/**
 * The {@code test} credential turned off under IAM enforcement alone, signatures not verified, so
 * that IAM enforcement is the check a request signed as {@code test} meets first.
 */
public class UnsignedDisabledTestCredentialProfile implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.of(
                "floci.auth.test-credential-enabled", "false",
                "floci.services.iam.enforcement-enabled", "true");
    }
}
