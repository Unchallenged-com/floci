package io.floci.aws.services.ssooidc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.RegionResolver;
import io.floci.aws.services.ssoadmin.SsoAdminService;
import io.floci.aws.services.ssooidc.model.TokenSession;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * Who a call made with an IAM Identity Center access token is, as CloudTrail names them: the user the token
 * was issued to, by its Identity Store user ID and the Identity Store's ARN, and the token's
 * {@code credentialId}, never the token.
 *
 * <p>Since July 14, 2025 "IAM Identity Center CloudTrail events will also specify IdentityCenterUser as the
 * identity type instead of Unknown", with the {@code onBehalfOf} element's {@code userId} and
 * {@code identityStoreArn} and the {@code credentialId} in place of {@code userName} and {@code principalId}
 * (AWS Security Blog, Important changes to CloudTrail events for AWS IAM Identity Center, 2024-11-19, updated
 * 2025-11-26). "The value of the {@code credentialId} field emitted for AWS access portal events invoked with
 * OIDC equals the ID of the access token"
 * (https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-cloudtrail-use-cases.html): Floci's tokens
 * carry no ID of their own, so it is derived from the token, one way.
 */
@ApplicationScoped
public class IdentityCenterCallers {

    private final SsoOidcService oidc;
    private final SsoAdminService ssoAdmin;
    private final RegionResolver regions;
    private final ObjectMapper mapper;

    @Inject
    public IdentityCenterCallers(SsoOidcService oidc, SsoAdminService ssoAdmin, RegionResolver regions,
                                 ObjectMapper mapper) {
        this.oidc = oidc;
        this.ssoAdmin = ssoAdmin;
        this.regions = regions;
        this.mapper = mapper;
    }

    /**
     * The {@code userIdentity} of a call made with {@code accessToken}, as the access portal's and CreateToken's
     * records give it; null for a token Floci does not know.
     */
    public ObjectNode userIdentity(String accessToken) {
        TokenSession session = session(accessToken);
        if (session == null) {
            return null;
        }
        ObjectNode identity = mapper.createObjectNode();
        identity.put("type", "IdentityCenterUser");
        identity.put("accountId", regions.getAccountId());
        if (session.principalId() != null) {
            identity.putObject("onBehalfOf")
                    .put("userId", session.principalId())
                    .put("identityStoreArn", identityStoreArn());
        }
        identity.put("credentialId", credentialId(accessToken));
        return identity;
    }

    /**
     * The user {@code accessToken} was issued for, as a 2026 record of CreateTokenWithIAM carries it in
     * {@code additionalEventData}; null for a token without one, or one Floci does not know.
     */
    public ObjectNode tokenUser(String accessToken) {
        TokenSession session = session(accessToken);
        if (session == null || session.principalId() == null) {
            return null;
        }
        return mapper.createObjectNode()
                .put("identitystore:UserId", session.principalId())
                .put("identitystore:IdentityStoreArn", identityStoreArn())
                .put("identitycenter:CredentialId", credentialId(accessToken));
    }

    /** The ID of the account's Identity Store, as CreateToken's record names it in {@code resources}. */
    public String identityStoreId() {
        return ssoAdmin.getIdentityStoreId();
    }

    private TokenSession session(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            return null;
        }
        try {
            return oidc.requireAccessToken(accessToken);
        } catch (SsoOidcException e) {
            return null;
        }
    }

    private String identityStoreArn() {
        return regions.buildGlobalArn("identitystore", regions.getAccountId(), "identitystore/" + identityStoreId());
    }

    private static String credentialId(String accessToken) {
        return UUID.nameUUIDFromBytes(("floci-sso-credential:" + accessToken).getBytes(StandardCharsets.UTF_8))
                .toString();
    }
}
