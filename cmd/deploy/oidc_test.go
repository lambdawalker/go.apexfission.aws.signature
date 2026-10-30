package main

import (
	"strings"
	"testing"
)

func TestOIDCTrustIsExactRepositoryEnvironment(t *testing.T) {
	p := oidcTrust(configData{Account: "123456789012", Repository: "owner/repo", Environment: "qa"})
	if !strings.Contains(p, "repo:owner/repo:environment:qa") || strings.Contains(p, "repo:owner/*") {
		t.Fatal(p)
	}
}
func TestOIDCPlanDoesNotMutate(t *testing.T) {
	c := configData{Account: "123456789012", Region: "us-east-1", Repository: "owner/repo", Environment: "dev", Backend: "s3://state/prefix"}
	r := &fakeRunner{responses: map[string]string{"aws sts get-caller-identity --output json": `{"Account":"123456789012"}`}}
	if e := oidcSetup(c, r, false, false); e != nil {
		t.Fatal(e)
	}
	for _, v := range r.calls {
		if strings.Contains(v, " create-") || strings.Contains(v, " put-") {
			t.Fatal(v)
		}
	}
}
func TestOIDCSetupRequiresApproval(t *testing.T) {
	if e := oidcSetup(configData{}, &fakeRunner{}, true, false); e == nil {
		t.Fatal("setup without approval")
	}
}
func TestDeploymentRoleCannotModifyBoundary(t *testing.T) {
	c := configData{Account: "123456789012", Region: "us-east-1", Environment: "dev", Backend: "s3://state/prefix"}
	p := deploymentPolicy(c)
	for _, bad := range []string{"iam:DeleteRolePermissionsBoundary", "iam:PutRolePermissionsBoundary", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:DeletePolicy"} {
		if strings.Contains(p, bad) {
			t.Fatal("deployer can change boundary", bad)
		}
	}
	for _, required := range []string{"iam:PermissionsBoundary", "kms:CreateGrant", "kms:GrantIsForAWSResource", "aws:ResourceTag/Environment"} {
		if !strings.Contains(p, required) {
			t.Fatal("missing enforcement", required)
		}
	}
}
