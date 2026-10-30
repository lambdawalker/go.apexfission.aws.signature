package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	pr "github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type mocks struct {
	sync.Mutex
	seen map[string]pr.PropertyMap
}

func (m *mocks) Call(a pulumi.MockCallArgs) (pr.PropertyMap, error) { return a.Args, nil }
func (m *mocks) NewResource(a pulumi.MockResourceArgs) (string, pr.PropertyMap, error) {
	m.Lock()
	defer m.Unlock()
	m.seen[a.TypeToken+":"+a.Name] = a.Inputs
	out := a.Inputs.Copy()
	out["arn"] = pr.NewStringProperty("arn:aws:mock:us-east-1:123456789012:" + a.Name)
	out["name"] = pr.NewStringProperty(a.Name)
	out["invokeArn"] = pr.NewStringProperty("arn:invoke:" + a.Name)
	out["executionArn"] = pr.NewStringProperty("arn:aws:execute-api:us-east-1:123456789012:" + a.Name)
	out["apiEndpoint"] = pr.NewStringProperty("https://example.execute-api.us-east-1.amazonaws.com")
	return a.Name + "-id", out, nil
}
func testRoot(t *testing.T) string {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
func TestResourcesEnforcePrivateEvidenceAndJWT(t *testing.T) {
	d := t.TempDir()
	zip := filepath.Join(d, "bootstrap.zip")
	os.WriteFile(zip, []byte("test artifact"), 0600)
	roots := testRoot(t)
	m := &mocks{seen: map[string]pr.PropertyMap{}}
	cfg := map[string]string{"sworn-ink:awsAccount": "123456789012", "aws:region": "us-east-1", "sworn-ink:jwtIssuer": "https://issuer.example", "sworn-ink:jwtAudience": "client", "sworn-ink:jwtScope": "sign", "sworn-ink:appPackage": "com.example.app", "sworn-ink:appDigests": strings.Repeat("a", 64), "sworn-ink:googleRootsPEM": roots, "sworn-ink:artifact": zip}
	e := pulumi.RunErr(deploy, pulumi.WithMocks("sworn-ink", "dev", m), func(info *pulumi.RunInfo) { info.Config = cfg })
	if e != nil {
		t.Fatal(e)
	}
	m.Lock()
	defer m.Unlock()
	for _, r := range []string{"challenges", "registrations", "signatures"} {
		args := m.seen["aws:apigatewayv2/route:Route:"+r]
		if args["authorizationType"].StringValue() != "JWT" || len(args["authorizationScopes"].ArrayValue()) != 1 {
			t.Fatal(args)
		}
	}
	key := m.seen["aws:kms/key:Key:receipt"]
	if key["keyUsage"].StringValue() != "SIGN_VERIFY" || key["customerMasterKeySpec"].StringValue() != "ECC_NIST_P256" {
		t.Fatal(key)
	}
	fn := m.seen["aws:lambda/function:Function:api"]
	if fn["runtime"].StringValue() != "provided.al2023" || fn["architectures"].ArrayValue()[0].StringValue() != "arm64" {
		t.Fatal(fn)
	}
	bucket := m.seen["aws:s3/bucket:Bucket:evidence"]
	if !bucket["versioning"].ObjectValue()["enabled"].BoolValue() {
		t.Fatal(bucket)
	}
	block := m.seen["aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock:private"]
	for _, k := range []pr.PropertyKey{"blockPublicAcls", "blockPublicPolicy", "ignorePublicAcls", "restrictPublicBuckets"} {
		if !block[k].BoolValue() {
			t.Fatal(k)
		}
	}
	role := m.seen["aws:iam/role:Role:lambda"]
	if !strings.HasSuffix(role["permissionsBoundary"].StringValue(), "policy/sworn-ink-dev-runtime-boundary") {
		t.Fatal("runtime boundary absent", role)
	}
	api := m.seen["aws:apigatewayv2/api:Api:http"]
	if api["tags"].ObjectValue()["Environment"].StringValue() != "dev" {
		t.Fatal("API tag missing", api)
	}
	table := m.seen["aws:dynamodb/table:Table:state"]
	if table["hashKey"].StringValue() != "pk" || table["ttl"].ObjectValue()["attributeName"].StringValue() != "ttlAt" {
		t.Fatal(table)
	}
}
