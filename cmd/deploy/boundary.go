package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

func runtimeBoundaryARN(c configData) string {
	return "arn:aws:iam::" + c.Account + ":policy/sworn-ink-" + c.Environment + "-runtime-boundary"
}

// Bootstrap-owned boundary is deliberately outside the deployment role's IAM scope.
func runtimeBoundary(c configData) string {
	prefix := "sworn-ink-" + c.Environment
	arn := func(service, path string) string {
		return "arn:aws:" + service + ":" + c.Region + ":" + c.Account + ":" + path
	}
	bucket := "arn:aws:s3:::sworn-ink-" + c.Account + "-" + c.Region + "-" + c.Environment + "-evidence"
	return jsonText(map[string]any{"Version": "2012-10-17", "Statement": []any{
		map[string]any{"Effect": "Allow", "Action": []string{"dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"}, "Resource": arn("dynamodb", "table/"+prefix+"-state")},
		map[string]any{"Effect": "Allow", "Action": []string{"s3:GetObject", "s3:PutObject"}, "Resource": bucket + "/evidence/*"},
		map[string]any{"Effect": "Allow", "Action": "s3:GetObject", "Resource": bucket + "/config/google-roots.pem"},
		map[string]any{"Effect": "Allow", "Action": []string{"logs:CreateLogStream", "logs:PutLogEvents"}, "Resource": arn("logs", "log-group:/aws/lambda/"+prefix+":*")},
		map[string]any{"Effect": "Allow", "Action": []string{"kms:GenerateDataKey", "kms:Decrypt", "kms:Sign", "kms:GetPublicKey"}, "Resource": arn("kms", "key/*"), "Condition": map[string]any{"StringEquals": map[string]string{"aws:ResourceTag/Project": "sworn-ink", "aws:ResourceTag/Environment": c.Environment}}}}})
}

func boundarySetup(c configData, r runner, apply, approved bool) error {
	if apply && !approved {
		return errors.New("boundary-setup requires --approve after reviewing boundary-plan")
	}
	env := []string{"AWS_REGION=" + c.Region}
	if c.Profile != "" {
		env = append(env, "AWS_PROFILE="+c.Profile)
	}
	run := func(args []string, in string) ([]byte, error) { return r.Run("aws", args, env, strings.NewReader(in)) }
	id, e := run([]string{"sts", "get-caller-identity", "--output", "json"}, "")
	if e != nil {
		return e
	}
	var identity struct{ Account string }
	if json.Unmarshal(id, &identity) != nil || identity.Account != c.Account {
		return errors.New("boundary bootstrap account mismatch")
	}
	fmt.Println("Runtime permissions boundary to review:\n" + runtimeBoundary(c))
	if !apply {
		return nil
	}
	runJSON := func(args []string, body string) ([]byte, error) {
		f, e := os.CreateTemp("", "sworn-ink-boundary-*.json")
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
	boundaryARN := runtimeBoundaryARN(c)
	boundaryName := "sworn-ink-" + c.Environment + "-runtime-boundary"
	boundaryDocument := runtimeBoundary(c)
	existingBoundary, err := run([]string{"iam", "get-policy", "--policy-arn", boundaryARN}, "")
	if err != nil {
		if !strings.Contains(err.Error(), "NoSuchEntity") {
			return err
		}
		body := jsonText(map[string]any{"PolicyName": boundaryName, "PolicyDocument": boundaryDocument})
		if _, err = runJSON([]string{"iam", "create-policy"}, body); err != nil {
			return err
		}
	} else {
		var v struct {
			Policy struct{ DefaultVersionId string }
		}
		if json.Unmarshal(existingBoundary, &v) != nil || v.Policy.DefaultVersionId == "" {
			return errors.New("cannot inspect boundary policy version")
		}
		version, err := run([]string{"iam", "get-policy-version", "--policy-arn", boundaryARN, "--version-id", v.Policy.DefaultVersionId}, "")
		if err != nil {
			return err
		}
		var p struct {
			PolicyVersion struct{ Document json.RawMessage }
		}
		if json.Unmarshal(version, &p) != nil || !sameJSON(p.PolicyVersion.Document, []byte(boundaryDocument)) {
			return errors.New("existing runtime boundary differs; privileged operator review required")
		}
	}
	fmt.Println("Runtime boundary ready:", boundaryARN)
	return nil
}
