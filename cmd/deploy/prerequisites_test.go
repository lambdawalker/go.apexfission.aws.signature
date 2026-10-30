package main

import "testing"

func TestPrerequisitesRejectOldVersions(t *testing.T) {
	r := &fakeRunner{responses: map[string]string{"go version": "go version go1.25.1 linux/amd64"}}
	if e := checkVersions(r, false); e == nil {
		t.Fatal("old Go accepted")
	}
}
