package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// validateTarget checks provider configuration as well as application config.
// STS verification alone cannot establish which region a Pulumi provider uses.
func validateTarget(c configData, r runner, env []string) error {
	get := func(key string) (string, error) {
		b, e := r.Run("pulumi", []string{"config", "get", key}, env, nil)
		return strings.TrimSpace(string(b)), e
	}
	region, e := get("aws:region")
	if e != nil || region != c.Region {
		return errors.New("Pulumi aws:region differs from selected target; explicit reconfiguration required")
	}
	account, e := get("awsAccount")
	if e != nil || account != c.Account {
		return errors.New("Pulumi awsAccount differs from selected target; explicit reconfiguration required")
	}
	allowed, e := get("aws:allowedAccountIds")
	var ids []string
	if e != nil || json.Unmarshal([]byte(allowed), &ids) != nil || len(ids) != 1 || ids[0] != c.Account {
		return errors.New("Pulumi provider must allow exactly the selected AWS account")
	}
	return nil
}

// restoreConfig always fetches authoritative configuration, even when a local
// YAML exists. Failed downloads preserve the local file and never trigger key
// regeneration. First setup is permitted only on explicit remote 404 with no
// local file; existing state without its encrypted YAML must be recovered.
func restoreConfig(r runner, env []string, local, remote string, allowNew bool) (bool, error) {
	f, e := os.CreateTemp(filepath.Dir(local), ".restore-*")
	if e != nil {
		return false, e
	}
	tmp := f.Name()
	f.Close()
	defer os.Remove(tmp)
	_, e = r.Run("aws", []string{"s3", "cp", remote, tmp}, env, nil)
	if e != nil {
		missing := strings.Contains(e.Error(), "(404)") || strings.Contains(e.Error(), "(NoSuchKey)") || strings.Contains(e.Error(), "(NotFound)")
		if allowNew && missing {
			if _, stat := os.Stat(local); os.IsNotExist(stat) {
				return false, nil
			}
			return false, errors.New("authoritative stack config absent but local YAML exists; recover explicitly rather than adopt another target's config")
		}
		return false, fmt.Errorf("cannot restore authoritative stack config; existing local config preserved: %w", e)
	}
	b, e := os.ReadFile(tmp)
	if e != nil {
		return false, e
	}
	if len(b) == 0 {
		return false, errors.New("empty authoritative stack configuration")
	}
	if e = atomicWrite(local, b); e != nil {
		return false, e
	}
	return true, nil
}
