package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfirmEOFIsCancellation(t *testing.T) {
	if confirm(strings.NewReader(""), &bytes.Buffer{}, time.Millisecond) {
		t.Fatal("EOF approved")
	}
}
func TestConfirmAnswers(t *testing.T) {
	for _, v := range []string{"n\n", "\x1b\n"} {
		if confirm(strings.NewReader(v), &bytes.Buffer{}, time.Second) {
			t.Fatal(v)
		}
	}
	if !confirm(strings.NewReader("\n"), &bytes.Buffer{}, time.Second) {
		t.Fatal("enter cancelled")
	}
}
func TestVaultRejectWrongPasswordWithoutMutation(t *testing.T) {
	b, e := seal([]byte("secret"), "pass")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = openVault(b, "wrong"); e == nil {
		t.Fatal("accepted wrong password")
	}
	p, e := openVault(b, "pass")
	if e != nil || string(p) != "secret" {
		t.Fatal(e)
	}
}
func TestFingerprintContentAndExclusions(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "go.mod"), []byte("a"), 0600)
	a, _ := fingerprint(d, "go1", "dev")
	os.Mkdir(filepath.Join(d, "build"), 0700)
	os.WriteFile(filepath.Join(d, "build", "out"), []byte("ignored"), 0600)
	b, _ := fingerprint(d, "go1", "dev")
	if a != b {
		t.Fatal("output invalidated build")
	}
	os.WriteFile(filepath.Join(d, "go.mod"), []byte("b"), 0600)
	b, _ = fingerprint(d, "go1", "dev")
	if a == b {
		t.Fatal("missed source change")
	}
}

func TestBuildReuseAndTamperDetection(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "go.mod"), []byte("module example"), 0600)
	r := &buildRunner{root: d}
	if e := build(d, "dev", r, false); e != nil {
		t.Fatal(e)
	}
	if e := build(d, "dev", r, false); e != nil {
		t.Fatal(e)
	}
	if r.builds != 1 {
		t.Fatal("unchanged rebuilt", r.builds)
	}
	os.WriteFile(filepath.Join(d, "build", "bootstrap.zip"), []byte("tampered"), 0600)
	if e := build(d, "dev", r, false); e != nil {
		t.Fatal(e)
	}
	if r.builds != 2 {
		t.Fatal("tampered artifact reused")
	}
	os.WriteFile(filepath.Join(d, "go.mod"), []byte("module changed"), 0600)
	if e := build(d, "dev", r, false); e != nil {
		t.Fatal(e)
	}
	if r.builds != 3 {
		t.Fatal("module change reused")
	}
}

type buildRunner struct {
	root   string
	builds int
}

func (r *buildRunner) Run(name string, args, env []string, in io.Reader) ([]byte, error) {
	if name == "go" && args[0] == "version" {
		return []byte("go version go1.26.6 linux/amd64"), nil
	}
	if name == "go" && args[0] == "build" {
		r.builds++
		return nil, os.WriteFile(args[3], []byte("ELF test"), 0700)
	}
	return nil, nil
}
func TestStateBucketChecksFailClosed(t *testing.T) {
	c := configData{Backend: "s3://bucket/prefix", Account: "123456789012", Region: "us-east-1"}
	r := &fakeRunner{responses: map[string]string{}}
	if e := verifyState(c, r, nil); e == nil {
		t.Fatal("missing versioning accepted")
	}
}
func TestConfirmTimeoutAndClosedPipe(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()
	if !confirm(reader, &bytes.Buffer{}, time.Millisecond) {
		t.Fatal("timeout cancelled")
	}
	reader, writer = io.Pipe()
	writer.Close()
	if confirm(reader, &bytes.Buffer{}, time.Second) {
		t.Fatal("closed input approved")
	}
}
func TestFingerprintRejectsExternalLocalReplacement(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "go.mod"), []byte("module example\nreplace example.org/local => ../external\n"), 0600)
	if _, e := fingerprint(d, "go1", "dev"); e == nil {
		t.Fatal("external replacement was silently cached")
	}
}

func TestEnvironmentNamesFitAWSResourceLimits(t *testing.T) {
	if environmentRE.MatchString(strings.Repeat("a", 17)) {
		t.Fatal("environment permits S3 evidence names longer than 63 bytes")
	}
	if !environmentRE.MatchString("abcdefghijklmnop") {
		t.Fatal("16-character environment should be supported")
	}
}
