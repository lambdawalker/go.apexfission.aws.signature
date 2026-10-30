package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func githubVars(c configData) map[string]string {
	return map[string]string{"DEPLOY_ACCOUNT": c.Account, "AWS_REGION": c.Region, "DEPLOY_BACKEND": c.Backend, "DEPLOY_ROLE_ARN": c.RoleARN, "DEPLOY_REPOSITORY": c.Repository, "DEPLOY_ENVIRONMENT": c.Environment, "DEPLOY_COMPONENT": "Backend"}
}
func githubFingerprint(vars map[string]string) string {
	b, _ := json.Marshal(struct {
		Schema    string
		Variables map[string]string
		Secrets   []string
	}{"sworn-ink-github-v1", vars, []string{"PULUMI_CONFIG_PASSPHRASE"}})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Reconciliation reads actual managed fields and secret inventory on every invocation.
// Protection settings are independently managed and are never sent in update requests.
func github(c configData, r runner, apply, approved bool) error {
	if c.Repository == "" || strings.Count(c.Repository, "/") != 1 {
		return errors.New("DEPLOY_REPOSITORY=owner/repo is required")
	}
	if apply && !approved {
		return errors.New("github-setup changes require --approve; inspect github-plan first")
	}
	if _, e := r.Run("gh", []string{"api", "user"}, nil, nil); e != nil {
		return e
	}
	b, e := r.Run("gh", []string{"repo", "view", c.Repository, "--json", "nameWithOwner"}, nil, nil)
	if e != nil {
		return e
	}
	var repo struct{ NameWithOwner string }
	if e = json.Unmarshal(b, &repo); e != nil || !strings.EqualFold(repo.NameWithOwner, c.Repository) {
		return errors.New("GitHub repository identity did not match")
	}
	base := "repos/" + c.Repository + "/environments/" + c.Environment
	b, e = r.Run("gh", []string{"api", base}, nil, nil)
	if e != nil {
		if !strings.Contains(e.Error(), "404") {
			return fmt.Errorf("cannot inspect environment (requires repository environment administration permission): %w", e)
		}
		fmt.Println("GitHub environment missing:", c.Environment)
		if !apply {
			return nil
		}
		if _, e = r.Run("gh", []string{"api", "--method", "PUT", base}, nil, nil); e != nil {
			return fmt.Errorf("create environment manually at https://github.com/%s/settings/environments: %w", c.Repository, e)
		}
		b = []byte(`{"name":"` + c.Environment + `"}`)
	}
	var environment struct{ Name string }
	if e = json.Unmarshal(b, &environment); e != nil || environment.Name != c.Environment {
		return errors.New("GitHub environment identity mismatch")
	}
	b, e = r.Run("gh", []string{"api", base + "/variables?per_page=100"}, nil, nil)
	if e != nil {
		return e
	}
	var variables struct {
		Variables []struct{ Name, Value string }
	}
	if e = json.Unmarshal(b, &variables); e != nil {
		return e
	}
	actual := map[string]string{}
	for _, v := range variables.Variables {
		actual[v.Name] = v.Value
	}
	b, e = r.Run("gh", []string{"api", base + "/secrets?per_page=100"}, nil, nil)
	if e != nil {
		return e
	}
	var secretNames struct{ Secrets []struct{ Name string } }
	if e = json.Unmarshal(b, &secretNames); e != nil {
		return e
	}
	hasPass := false
	for _, s := range secretNames.Secrets {
		if s.Name == "PULUMI_CONFIG_PASSPHRASE" {
			hasPass = true
		}
	}
	desired := githubVars(c)
	keys := []string{"DEPLOY_ACCOUNT", "AWS_REGION", "DEPLOY_BACKEND", "DEPLOY_ROLE_ARN", "DEPLOY_REPOSITORY", "DEPLOY_ENVIRONMENT", "DEPLOY_COMPONENT"}
	for _, key := range keys {
		if desired[key] != actual[key] {
			fmt.Println("GitHub managed variable requires reconciliation:", key)
			if apply {
				if _, e = r.Run("gh", []string{"variable", "set", key, "--repo", c.Repository, "--env", c.Environment, "--body", desired[key]}, nil, nil); e != nil {
					return e
				}
			}
		}
	}
	if !hasPass {
		fmt.Println("GitHub requires secret PULUMI_CONFIG_PASSPHRASE; its value cannot be read back")
		if apply {
			pass := os.Getenv("PULUMI_CONFIG_PASSPHRASE")
			if pass == "" {
				home, err := os.UserConfigDir()
				if err != nil {
					return err
				}
				vault, err := os.ReadFile(filepath.Join(home, "sworn-ink", c.Environment, "secrets.v1"))
				if err != nil {
					return errors.New("missing secret and vault; configure PULUMI_CONFIG_PASSPHRASE securely")
				}
				unlock, err := hidden("Local vault unlock password")
				if err != nil {
					return err
				}
				plain, err := openVault(vault, unlock)
				if err != nil {
					return err
				}
				pass = string(plain)
			}
			if _, e = r.Run("gh", []string{"secret", "set", "PULUMI_CONFIG_PASSPHRASE", "--repo", c.Repository, "--env", c.Environment}, nil, strings.NewReader(pass)); e != nil {
				return e
			}
		}
	}
	marker := githubFingerprint(desired)

	if apply && marker != actual["DEPLOY_CONFIG_SHA256"] {
		if _, e = r.Run("gh", []string{"variable", "set", "DEPLOY_CONFIG_SHA256", "--repo", c.Repository, "--env", c.Environment, "--body", marker}, nil, nil); e != nil {
			return e
		}
	}
	fmt.Printf("GitHub environment https://github.com/%s/settings/environments; component Backend/%s\n", c.Repository, c.Environment)
	fmt.Println("OIDC role trust and least-privilege deployment permissions must be provisioned and reviewed separately; this command does not create IAM trust or change protection rules.")
	return nil
}
