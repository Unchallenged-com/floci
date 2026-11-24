package io.floci.aws.services.signin;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.RegionResolver;
import io.floci.aws.core.common.RequestSourceAddress;
import io.floci.aws.services.cloudtrail.CloudTrailService;
import io.floci.aws.services.signin.model.AuthorizationRequest;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

/**
 * Records the two calls of an {@code aws login} in CloudTrail, as the IAM user guide's 2025 records of them
 * show (https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html, Example sign-in events in
 * CloudTrail log): AuthorizeOAuth2Access when the signed-in user grants the authorization code, and
 * CreateOAuth2Token when the CLI exchanges a code or a refresh token for credentials. Both are
 * {@code signin.amazonaws.com} management events, read-only, with {@code "responseElements": null} and
 * {@code "additionalEventData": {"success": "true", "x-amzn-vpce-id": ""}}, and name the signed-in principal
 * without an access key.
 *
 * <ul>
 *   <li>AuthorizeOAuth2Access keeps {@code scope}, {@code redirect_uri}, {@code code_challenge_method} and
 *   {@code client_id}, and none of {@code code_challenge}, {@code state} or {@code response_type}.</li>
 *   <li>CreateOAuth2Token keeps only {@code client_id}: neither the code, the verifier, the refresh token nor
 *   the credentials it answers are recorded.</li>
 * </ul>
 *
 * <p>Floci's sign-in grants the account's root user, whose credentials the token call issues, so both records
 * are the root user's ({@code "type": "Root"}).
 */
@ApplicationScoped
public class SigninCloudTrailEvents {

    private static final String EVENT_SOURCE = "signin.amazonaws.com";

    private final CloudTrailService cloudTrail;
    private final RegionResolver regions;
    private final CurrentVertxRequest currentRequest;
    private final ObjectMapper mapper;

    @Inject
    public SigninCloudTrailEvents(CloudTrailService cloudTrail, RegionResolver regions,
                                  CurrentVertxRequest currentRequest, ObjectMapper mapper) {
        this.cloudTrail = cloudTrail;
        this.regions = regions;
        this.currentRequest = currentRequest;
        this.mapper = mapper;
    }

    /**
     * Records that the user granted {@code request}. Sign-in accepts only {@code scope=openid} and
     * {@code code_challenge_method=SHA-256}, which the record carries as they were sent.
     */
    public void authorized(AuthorizationRequest request) {
        ObjectNode parameters = mapper.createObjectNode()
                .put("scope", "openid")
                .put("redirect_uri", request.redirectUri())
                .put("code_challenge_method", "SHA-256")
                .put("client_id", request.clientId());
        record("AuthorizeOAuth2Access", request.accountId(), parameters);
    }

    /** Records that the CLI {@code clientId} was issued credentials of the account's root user. */
    public void tokenCreated(String clientId) {
        record("CreateOAuth2Token", regions.getAccountId(), mapper.createObjectNode().put("client_id", clientId));
    }

    private void record(String eventName, String accountId, ObjectNode parameters) {
        ObjectNode identity = mapper.createObjectNode()
                .put("type", "Root")
                .put("principalId", accountId)
                .put("arn", regions.buildGlobalArn("iam", accountId, "root"))
                .put("accountId", accountId);
        ObjectNode additional = mapper.createObjectNode().put("success", "true").put("x-amzn-vpce-id", "");
        RoutingContext context = currentRequest.getCurrent();
        HttpServerRequest http = context == null ? null : context.request();
        cloudTrail.emitManagementEvent(new CloudTrailService.ManagementEventInput(EVENT_SOURCE, eventName, null,
                null, parameters, null, true, http == null ? null : RequestSourceAddress.of(http),
                http == null ? null : http.getHeader("User-Agent"), null, null, null, false, identity, additional,
                null));
    }
}
