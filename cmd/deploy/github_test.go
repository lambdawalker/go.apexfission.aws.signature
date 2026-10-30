package main

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
)

type fakeRunner struct {
	calls     []string
	responses map[string]string
}

func (r *fakeRunner) Run(name string, args, env []string, in io.Reader) ([]byte, error) {
	key := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, key)
	return []byte(r.responses[key]), nil
}
func TestReconcileChecksFieldsEvenWithMatchingMarker(t *testing.T) {
	c := configData{Environment: "dev", Account: "123456789012", Region: "us-east-1", Backend: "s3://state/prefix", Repository: "owner/repo", RoleARN: "arn:aws:iam::123456789012:role/deploy"}
	r := &fakeRunner{responses: map[string]string{}}
	desired := githubVars(c)
	marker := githubFingerprint(desired)
	r.responses["gh api repos/owner/repo/environments/dev/variables?per_page=100"] = `{"variables":[{"name":"DEPLOY_CONFIG_SHA256","value":"` + marker + `"}]}`
	r.responses["gh api repos/owner/repo/environments/dev/secrets?per_page=100"] = `{"secrets":[{"name":"PULUMI_CONFIG_PASSPHRASE"}]}`
	r.responses["gh api user"] = `{"login":"operator"}`
	r.responses["gh repo view owner/repo --json nameWithOwner"] = `{"nameWithOwner":"owner/repo"}`
	r.responses["gh api repos/owner/repo/environments/dev"] = `{"name":"dev","protection_rules":[{"type":"required_reviewers"}]}`
	if e := github(c, r, true, true); e != nil {
		t.Fatal(e)
	}
	found := false
	for _, v := range r.calls {
		if strings.Contains(v, "gh variable set DEPLOY_ACCOUNT") {
			found = true
		}
	}
	if !found {
		t.Fatal("matching marker hid missing variables", r.calls)
	}
}
func TestGitHubPlanDoesNotWrite(t *testing.T) {
	r := &fakeRunner{responses: map[string]string{"gh api user": `{"login":"operator"}`, "gh repo view o/r --json nameWithOwner": `{"nameWithOwner":"o/r"}`, "gh api repos/o/r/environments/dev": `{"name":"dev"}`, "gh api repos/o/r/environments/dev/variables?per_page=100": `{"variables":[]}`, "gh api repos/o/r/environments/dev/secrets?per_page=100": `{"secrets":[]}`}}
	if e := github(configData{Repository: "o/r", Environment: "dev"}, r, false, false); e != nil {
		t.Fatal(e)
	}
	for _, v := range r.calls {
		if strings.Contains(v, " set ") || strings.Contains(v, "--method") {
			t.Fatal(v)
		}
	}
}
func TestConfigFingerprintCanonical(t *testing.T) {
	a := githubFingerprint(map[string]string{"a": "bc", "d": "e"})
	b := githubFingerprint(map[string]string{"a": "b", "cd": "e"})
	if a == b {
		t.Fatal("ambiguous fields")
	}
	var m map[string]string
	json.Unmarshal([]byte(`{"d":"e","a":"bc"}`), &m)
	if a != githubFingerprint(m) {
		t.Fatal("unstable map ordering")
	}
}
