package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type targetRunner struct {
	values  map[string]string
	err     error
	content string
}

func (r targetRunner) Run(name string, args, env []string, in io.Reader) ([]byte, error) {
	if name == "pulumi" && len(args) > 2 && args[0] == "config" && args[1] == "get" {
		v, ok := r.values[args[2]]
		if !ok {
			return nil, errors.New("missing")
		}
		return []byte(v), nil
	}
	if r.err != nil {
		return nil, r.err
	}
	if name == "aws" && args[0] == "s3" && args[1] == "cp" {
		return nil, os.WriteFile(args[3], []byte(r.content), 0600)
	}
	return nil, errors.New("unexpected command")
}
func TestTargetProviderMustMatchPrintedTarget(t *testing.T) {
	c := configData{Account: "123456789012", Region: "us-east-2"}
	good := map[string]string{"aws:region": c.Region, "awsAccount": c.Account, "aws:allowedAccountIds": `["123456789012"]`}
	if err := validateTarget(c, targetRunner{values: good}, nil); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"aws:region", "awsAccount", "aws:allowedAccountIds"} {
		v := good[k]
		good[k] = "wrong"
		if validateTarget(c, targetRunner{values: good}, nil) == nil {
			t.Fatal("accepted stale", k)
		}
		good[k] = v
	}
	good["aws:allowedAccountIds"] = `["123456789012","999999999999"]`
	if validateTarget(c, targetRunner{values: good}, nil) == nil {
		t.Fatal("accepted broader provider account allowlist")
	}
}
func TestRestoreOverwritesStaleLocalConfigOnlyAfterSuccess(t *testing.T) {
	p := filepath.Join(t.TempDir(), "Pulumi.dev.yaml")
	os.WriteFile(p, []byte("stale"), 0600)
	r := targetRunner{content: "authoritative"}
	ok, e := restoreConfig(r, nil, p, "s3://bucket/prefix/config", false)
	if e != nil || !ok {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "authoritative" {
		t.Fatal("stale local reused")
	}
	r.err = errors.New("AccessDenied")
	if _, e = restoreConfig(r, nil, p, "s3://bucket/prefix/config", true); e == nil {
		t.Fatal("access failure accepted")
	}
	b, _ = os.ReadFile(p)
	if string(b) != "authoritative" {
		t.Fatal("restore failure destroyed existing config")
	}
}
func TestRestoreNewStackNeedsExplicitNotFoundAndNoLocalConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "Pulumi.dev.yaml")
	r := targetRunner{err: errors.New("HeadObject (404) Not Found")}
	ok, e := restoreConfig(r, nil, p, "s3://bucket/prefix/config", true)
	if e != nil || ok {
		t.Fatal(e)
	}
	if _, e = restoreConfig(r, nil, p, "s3://bucket/prefix/config", false); e == nil {
		t.Fatal("preview allowed missing config")
	}
	os.WriteFile(p, []byte("stale"), 0600)
	if _, e = restoreConfig(r, nil, p, "s3://bucket/prefix/config", true); e == nil || !strings.Contains(e.Error(), "local") {
		t.Fatal("adopted local config from another target", e)
	}
}
