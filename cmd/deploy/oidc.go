package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"
)

func jsonText(v any) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) }
func oidcTrust(c configData) string {
	return jsonText(map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Principal": map[string]string{"Federated": "arn:aws:iam::" + c.Account + ":oidc-provider/token.actions.githubusercontent.com"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": map[string]any{"StringEquals": map[string]string{"token.actions.githubusercontent.com:aud": "sts.amazonaws.com", "token.actions.githubusercontent.com:sub": "repo:" + c.Repository + ":environment:" + c.Environment}}}}})
}
func deploymentPolicy(c configData) string {
	prefix := "sworn-ink-" + c.Environment
	arn := func(service, resource string) string {
		return "arn:aws:" + service + ":" + c.Region + ":" + c.Account + ":" + resource
	}
	stateParts := strings.SplitN(strings.TrimPrefix(c.Backend, "s3://"), "/", 2)
	stateBucket := stateParts[0]
	statePrefix := ""
	if len(stateParts) == 2 {
		statePrefix = stateParts[1] + "/" + c.Environment + "/*"
	}
	evidence := "arn:aws:s3:::sworn-ink-" + c.Account + "-" + c.Region + "-" + c.Environment + "-evidence"
	stmt := func(actions []string, resources []string) map[string]any {
		return map[string]any{"Effect": "Allow", "Action": actions, "Resource": resources}
	}
	statements := []any{
		stmt([]string{"s3:GetBucketLocation", "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration", "s3:GetBucketPublicAccessBlock", "s3:ListBucket"}, []string{"arn:aws:s3:::" + stateBucket}),
		stmt([]string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject"}, []string{"arn:aws:s3:::" + stateBucket + "/" + statePrefix}),
		stmt([]string{"s3:CreateBucket", "s3:DeleteBucket", "s3:GetBucketLocation", "s3:GetBucketVersioning", "s3:PutBucketVersioning", "s3:GetEncryptionConfiguration", "s3:PutEncryptionConfiguration", "s3:GetBucketPublicAccessBlock", "s3:PutBucketPublicAccessBlock", "s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:GetBucketTagging", "s3:PutBucketTagging", "s3:ListBucket", "s3:GetBucketAcl", "s3:GetBucketCORS", "s3:GetBucketWebsite", "s3:GetLifecycleConfiguration", "s3:GetReplicationConfiguration", "s3:GetAccelerateConfiguration", "s3:GetBucketRequestPayment", "s3:GetBucketLogging", "s3:GetBucketObjectLockConfiguration", "s3:GetBucketOwnershipControls", "s3:GetBucketNotification"}, []string{evidence}),
		stmt([]string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:GetObjectTagging", "s3:PutObjectTagging"}, []string{evidence + "/config/google-roots.pem"}),
		stmt([]string{"dynamodb:CreateTable", "dynamodb:DeleteTable", "dynamodb:DescribeTable", "dynamodb:UpdateTable", "dynamodb:DescribeTimeToLive", "dynamodb:UpdateTimeToLive", "dynamodb:DescribeContinuousBackups", "dynamodb:UpdateContinuousBackups", "dynamodb:ListTagsOfResource", "dynamodb:TagResource", "dynamodb:UntagResource", "dynamodb:DescribeContributorInsights"}, []string{arn("dynamodb", "table/"+prefix+"-state")}),
		stmt([]string{"lambda:CreateFunction", "lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration", "lambda:DeleteFunction", "lambda:AddPermission", "lambda:RemovePermission", "lambda:GetPolicy", "lambda:ListVersionsByFunction", "lambda:ListTags", "lambda:TagResource", "lambda:UntagResource", "lambda:GetFunctionCodeSigningConfig", "lambda:GetFunctionConcurrency"}, []string{arn("lambda", "function:"+prefix)}),
		stmt([]string{"logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:PutRetentionPolicy", "logs:DeleteRetentionPolicy", "logs:ListTagsLogGroup", "logs:TagLogGroup", "logs:UntagLogGroup"}, []string{arn("logs", "log-group:/aws/lambda/"+prefix), arn("logs", "log-group:/aws/lambda/"+prefix+":*")}),
		stmt([]string{"logs:DescribeLogGroups"}, []string{"*"}),
		stmt([]string{"iam:GetRole", "iam:UpdateAssumeRolePolicy", "iam:DeleteRole", "iam:PutRolePolicy", "iam:GetRolePolicy", "iam:DeleteRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:ListInstanceProfilesForRole", "iam:TagRole", "iam:UntagRole"}, []string{"arn:aws:iam::" + c.Account + ":role/" + prefix + "-lambda"}),
		map[string]any{"Effect": "Allow", "Action": "iam:CreateRole", "Resource": "arn:aws:iam::" + c.Account + ":role/" + prefix + "-lambda", "Condition": map[string]any{"StringEquals": map[string]string{"iam:PermissionsBoundary": runtimeBoundaryARN(c)}}},
		map[string]any{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "arn:aws:iam::" + c.Account + ":role/" + prefix + "-lambda", "Condition": map[string]any{"StringEquals": map[string]string{"iam:PassedToService": "lambda.amazonaws.com"}}},
		// AWS does not provide resource scoping for CreateKey. Request tags bind creation;
		// subsequent management is restricted to tagged keys for this environment.
		map[string]any{"Effect": "Allow", "Action": "kms:CreateKey", "Resource": "*", "Condition": map[string]any{"StringEquals": map[string]string{"aws:RequestTag/Project": "sworn-ink", "aws:RequestTag/Environment": c.Environment}}},
		map[string]any{"Effect": "Allow", "Action": []string{"kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:EnableKeyRotation", "kms:ListResourceTags", "kms:TagResource", "kms:UntagResource", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion", "kms:PutKeyPolicy", "kms:GenerateDataKey", "kms:Decrypt"}, "Resource": arn("kms", "key/*"), "Condition": map[string]any{"StringEquals": map[string]string{"aws:ResourceTag/Project": "sworn-ink", "aws:ResourceTag/Environment": c.Environment}}},
		map[string]any{"Effect": "Allow", "Action": "kms:CreateGrant", "Resource": arn("kms", "key/*"), "Condition": map[string]any{"Bool": map[string]string{"kms:GrantIsForAWSResource": "true"}, "StringEquals": map[string]string{"aws:ResourceTag/Project": "sworn-ink", "aws:ResourceTag/Environment": c.Environment}}},
		// API and descendant management remains fail-closed unless AWS evaluates inherited
		// tag conditions for that operation. Never broaden this to all regional APIs.
		map[string]any{"Effect": "Allow", "Action": "apigateway:POST", "Resource": "arn:aws:apigateway:" + c.Region + "::/apis", "Condition": map[string]any{"StringEquals": map[string]string{"aws:RequestTag/Project": "sworn-ink", "aws:RequestTag/Environment": c.Environment}}},
		map[string]any{"Effect": "Allow", "Action": []string{"apigateway:GET", "apigateway:POST", "apigateway:PUT", "apigateway:PATCH", "apigateway:DELETE"}, "Resource": []string{"arn:aws:apigateway:" + c.Region + "::/apis/*", "arn:aws:apigateway:" + c.Region + "::/tags/*"}, "Condition": map[string]any{"StringEquals": map[string]string{"aws:ResourceTag/Project": "sworn-ink", "aws:ResourceTag/Environment": c.Environment}}},
	}
	return jsonText(map[string]any{"Version": "2012-10-17", "Statement": statements})
}
func sameJSON(a, b []byte) bool {
	var av, bv any
	if json.Unmarshal(a, &av) != nil || json.Unmarshal(b, &bv) != nil {
		return false
	}
	return reflect.DeepEqual(av, bv)
}

// The bootstrap command is separate from normal deployment. Existing trust/policies
// must exactly match; drift or independently managed role policies fail for review.
func oidcSetup(c configData, r runner, apply, approved bool) error {
	if apply && !approved {
		return errors.New("OIDC setup requires --approve after reviewing oidc-plan")
	}
	if c.Repository == "" || strings.Count(c.Repository, "/") != 1 {
		return errors.New("DEPLOY_REPOSITORY=owner/repo required")
	}
	env := []string{"AWS_REGION=" + c.Region}
	if c.Profile != "" {
		env = append(env, "AWS_PROFILE="+c.Profile)
	}
	run := func(args []string, in string) ([]byte, error) { return r.Run("aws", args, env, strings.NewReader(in)) }
	identity, e := run([]string{"sts", "get-caller-identity", "--output", "json"}, "")
	if e != nil {
		return e
	}
	var id struct{ Account string }
	if json.Unmarshal(identity, &id) != nil || id.Account != c.Account {
		return errors.New("OIDC bootstrap identity account mismatch")
	}
	roleName := "sworn-ink-" + c.Environment + "-github-deploy"
	expectedARN := "arn:aws:iam::" + c.Account + ":role/" + roleName
	if c.RoleARN != "" && c.RoleARN != expectedARN {
		return errors.New("OIDC bootstrap manages only " + expectedARN + "; independently supplied roles require operator verification")
	}
	trust := oidcTrust(c)
	policy := deploymentPolicy(c)
	fmt.Println("OIDC trust to review:\n" + trust)
	fmt.Println("Deployment IAM policy to review:\n" + policy)
	fmt.Println("Runtime permissions boundary to review:\n" + runtimeBoundary(c))
	if !apply {
		return nil
	}
	runJSON := func(args []string, body string) ([]byte, error) {
		f, e := os.CreateTemp("", "sworn-ink-iam-*.json")
		if e != nil {
			return nil, e
		}
		defer os.Remove(f.Name())
		if _, e = f.WriteString(body); e != nil {
			f.Close()
			return nil, e
		}
		if e = f.Close(); e != nil {
			return nil, e
		}
		return run(append(args, "--cli-input-json", "file://"+f.Name()), "")
	}
	if e := boundarySetup(c, r, true, true); e != nil {
		return e
	}
	providerARN := "arn:aws:iam::" + c.Account + ":oidc-provider/token.actions.githubusercontent.com"
	provider, e := run([]string{"iam", "get-open-id-connect-provider", "--open-id-connect-provider-arn", providerARN}, "")
	if e != nil {
		if !strings.Contains(e.Error(), "NoSuchEntity") {
			return e
		}
		if _, e = run([]string{"iam", "create-open-id-connect-provider", "--url", "https://token.actions.githubusercontent.com", "--client-id-list", "sts.amazonaws.com"}, ""); e != nil {
			return e
		}
	} else {
		var p struct {
			Url          string
			ClientIDList []string
		}
		if e = json.Unmarshal(provider, &p); e != nil {
			return e
		}
		compatible := p.Url == "token.actions.githubusercontent.com" || p.Url == "https://token.actions.githubusercontent.com"
		aud := false
		for _, v := range p.ClientIDList {
			aud = aud || v == "sts.amazonaws.com"
		}
		if !compatible || !aud {
			return errors.New("existing OIDC provider differs; review manually, existing provider not overwritten")
		}
	}
	role, e := run([]string{"iam", "get-role", "--role-name", roleName}, "")
	if e != nil {
		if !strings.Contains(e.Error(), "NoSuchEntity") {
			return e
		}
		body := jsonText(map[string]any{"RoleName": roleName, "AssumeRolePolicyDocument": trust, "Tags": []any{map[string]string{"Key": "Project", "Value": "sworn-ink"}, map[string]string{"Key": "Environment", "Value": c.Environment}}})
		if _, e = runJSON([]string{"iam", "create-role"}, body); e != nil {
			return e
		}
	} else {
		var v struct {
			Role struct {
				Arn                      string
				AssumeRolePolicyDocument json.RawMessage
			}
		}
		if e = json.Unmarshal(role, &v); e != nil {
			return e
		}
		raw := v.Role.AssumeRolePolicyDocument
		if len(raw) > 0 && raw[0] == '"' {
			var s string
			json.Unmarshal(raw, &s)
			decoded, e := url.QueryUnescape(s)
			if e != nil {
				return e
			}
			raw = []byte(decoded)
		}
		if v.Role.Arn != expectedARN || !sameJSON(raw, []byte(trust)) {
			return errors.New("existing role trust differs; no unrelated trust will be overwritten")
		}
	}
	existing, e := run([]string{"iam", "get-role-policy", "--role-name", roleName, "--policy-name", "sworn-ink-deployment"}, "")
	if e == nil {
		var p struct{ PolicyDocument json.RawMessage }
		if json.Unmarshal(existing, &p) != nil || !sameJSON(p.PolicyDocument, []byte(policy)) {
			return errors.New("existing deployment policy differs; review explicit rotation before changing")
		}
	} else {
		if !strings.Contains(e.Error(), "NoSuchEntity") {
			return e
		}
		body := jsonText(map[string]any{"RoleName": roleName, "PolicyName": "sworn-ink-deployment", "PolicyDocument": policy})
		if _, e = runJSON([]string{"iam", "put-role-policy"}, body); e != nil {
			return e
		}
	}
	fmt.Println("OIDC bootstrap role:", expectedARN)
	fmt.Println("Setup complete for managed trust/policy; review existing additional role policies independently. No workflow was dispatched.")
	return nil
}
