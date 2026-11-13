package infrastructure

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

func TestResourceIdentityRejectsUnrepresentableBucketNames(t *testing.T) {
	if validateResourceIdentity("abcdefghijklmnopq", "123456789012", "ap-southeast-7") == nil {
		t.Fatal("accepted environment above supported limit")
	}
	if e := validateResourceIdentity("abcdefghijklmnop", "123456789012", "ap-southeast-7"); e != nil {
		t.Fatal(e)
	}
}
