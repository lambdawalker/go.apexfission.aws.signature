package main

import (
	"strings"
	"testing"
)

func TestValidateFailsClosed(t *testing.T) {
	c := settings{Issuer: "https://issuer.example", Audience: "client", Scope: "sign", Package: "com.example.app", Digests: strings.Repeat("a", 64), Roots: "invalid"}
	if c.validate() == nil {
		t.Fatal("accepted invalid roots")
	}
	c.Roots = ""
	if c.validate() == nil {
		t.Fatal("accepted absent roots")
	}
}
func TestIAMHasNoWildcardResource(t *testing.T) {
	p := lambdaPolicy("table", "bucket", "storage", "receipt")
	if strings.Contains(p, `"Resource":"*"`) {
		t.Fatal(p)
	}
	for _, v := range []string{"dynamodb:UpdateItem", "evidence/*", "kms:Sign"} {
		if !strings.Contains(p, v) {
			t.Fatal(v, p)
		}
	}
}
