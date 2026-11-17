package io.floci.aws.services.iam;

import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;

class IamCloudTrailEventsTest {

    private static MultivaluedMap<String, String> params(String... pairs) {
        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            params.putSingle(pairs[i], pairs[i + 1]);
        }
        return params;
    }

    @ParameterizedTest
    @CsvSource({"GetUser,true", "ListAccessKeys,true", "GenerateCredentialReport,true",
            "SimulatePrincipalPolicy,true", "CreateUser,false", "UpdateAccessKey,false", "PutRolePolicy,false",
            "TagUser,false", "DeleteUser,false"})
    void readOnlyFollowsTheServiceReferenceAccessLevels(String action, boolean readOnly) {
        assertThat(IamCloudTrailEvents.isReadOnly(action), equalTo(readOnly));
    }

    @Test
    void requestParametersAreTheMembersWithALowerFirstLetterAndTheirModelTypes() {
        ObjectNode read = IamCloudTrailEvents.requestParameters("CreateRole", params("Action", "CreateRole",
                "Version", "2010-05-08", "RoleName", "ops", "AssumeRolePolicyDocument", "{\"Version\":\"2012-10-17\"}",
                "MaxSessionDuration", "7200", "Tags.member.1.Key", "team", "Tags.member.1.Value", "it",
                "Tags.member.2.Key", "env", "Tags.member.2.Value", "prod"));
        assertThat(read.path("roleName").asText(), equalTo("ops"));
        assertThat(read.path("assumeRolePolicyDocument").asText(), equalTo("{\"Version\":\"2012-10-17\"}"));
        assertThat(read.path("maxSessionDuration").isNumber(), equalTo(true));
        assertThat(read.path("maxSessionDuration").asInt(), equalTo(7200));
        assertThat(read.path("tags").size(), equalTo(2));
        assertThat(read.path("tags").get(1).path("key").asText(), equalTo("env"));
        assertThat(read.path("tags").get(1).path("value").asText(), equalTo("prod"));
        assertThat(read.has("action"), equalTo(false));
    }

    @Test
    void aCallWhoseOnlyMembersArePasswordsHasNoRequestParameters() {
        assertThat(IamCloudTrailEvents.requestParameters("ChangePassword",
                params("Action", "ChangePassword", "OldPassword", "old-one", "NewPassword", "new-one")), nullValue());
    }

    @Test
    void theResultLeavesSecretsOutAndWritesTimestampsAsCloudTrailDoes() {
        String xml = """
                <CreateAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
                  <CreateAccessKeyResult><AccessKey>
                    <UserName>alice</UserName><AccessKeyId>AKIAIOSFODNN7EXAMPLE</AccessKeyId>
                    <Status>Active</Status><SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</SecretAccessKey>
                    <CreateDate>2023-07-19T21:25:09Z</CreateDate>
                  </AccessKey></CreateAccessKeyResult>
                  <ResponseMetadata><RequestId>7a62c49f-347e-4fc4-9331-6e8eEXAMPLE</RequestId></ResponseMetadata>
                </CreateAccessKeyResponse>""";
        ObjectNode result = IamCloudTrailEvents.result("CreateAccessKey", xml);
        assertThat(result.path("accessKey").path("accessKeyId").asText(), equalTo("AKIAIOSFODNN7EXAMPLE"));
        assertThat(result.path("accessKey").has("secretAccessKey"), equalTo(false));
        assertThat(result.path("accessKey").path("createDate").asText(), equalTo("Jul 19, 2023 9:25:09 PM"));
    }

    @ParameterizedTest
    @CsvSource({"NoSuchEntity,NoSuchEntityException", "DeleteConflict,DeleteConflictException",
            "MalformedPolicyDocument,MalformedPolicyDocumentException", "ReportInProgress,CredentialReportNotReadyException",
            "AccessDenied,AccessDenied", "ValidationError,ValidationError"})
    void modeledErrorsAreRecordedUnderTheirShapesName(String code, String recorded) {
        assertThat(IamCloudTrailEvents.recordedErrorCode(code), equalTo(recorded));
    }

    @ParameterizedTest
    @CsvSource({"CreateUser,true", "UpdateAccessKey,true", "GetUser,false", "ListRoles,false",
            "ListSAMLProviders,false", "SimulatePrincipalPolicy,false"})
    void onlyCallsThatAreNotReadOnlyCarryTheirResult(String action, boolean recorded) {
        assertThat(IamCloudTrailEvents.recordsResult(action), equalTo(recorded));
    }

    @Test
    void theResultTypesBooleansAndCounts() {
        String xml = """
                <CreatePolicyResponse><CreatePolicyResult><Policy>
                  <PolicyName>Level3</PolicyName><DefaultVersionId>v1</DefaultVersionId>
                  <AttachmentCount>0</AttachmentCount><PermissionsBoundaryUsageCount>0</PermissionsBoundaryUsageCount>
                  <IsAttachable>true</IsAttachable><PolicyId>ANPAHI17SXDY4VPL1N1K8</PolicyId>
                </Policy></CreatePolicyResult></CreatePolicyResponse>""";
        ObjectNode policy = (ObjectNode) IamCloudTrailEvents.result("CreatePolicy", xml).path("policy");
        assertThat(policy.path("attachmentCount").isNumber(), equalTo(true));
        assertThat(policy.path("permissionsBoundaryUsageCount").isNumber(), equalTo(true));
        assertThat(policy.path("isAttachable").isBoolean(), equalTo(true));
        assertThat(policy.path("defaultVersionId").asText(), equalTo("v1"));
    }

    @Test
    void aListInTheResultIsAnArrayAndAnEmptyResultIsNull() {
        String xml = """
                <AddUserToGroupResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
                  <ResponseMetadata><RequestId>1</RequestId></ResponseMetadata>
                </AddUserToGroupResponse>""";
        assertThat(IamCloudTrailEvents.result("AddUserToGroup", xml), nullValue());
        String listed = """
                <CreatePolicyVersionResponse><CreatePolicyVersionResult><PolicyVersion>
                  <VersionId>v2</VersionId><IsDefaultVersion>true</IsDefaultVersion>
                  <Tags><member><Key>a</Key><Value>1</Value></member></Tags>
                </PolicyVersion></CreatePolicyVersionResult></CreatePolicyVersionResponse>""";
        ObjectNode result = IamCloudTrailEvents.result("CreatePolicyVersion", listed);
        assertThat(result.path("policyVersion").path("tags").get(0).path("key").asText(), equalTo("a"));
    }
}
