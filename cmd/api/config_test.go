package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestRootsRejectGarbageAndNonCA(t *testing.T) {
	if _, e := parseRoots([]byte("garbage")); e == nil {
		t.Fatal("accepted garbage")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, _ := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if _, e := parseRoots(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); e == nil {
		t.Fatal("accepted nonCA")
	}
	c.IsCA = true
	c.BasicConstraintsValid = true
	c.KeyUsage = x509.KeyUsageCertSign
	der, _ = x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if _, e := parseRoots(b); e != nil {
		t.Fatal(e)
	}
	if _, e := parseRoots(append(b, []byte("junk")...)); e == nil {
		t.Fatal("accepted trailing junk")
	}
}
func TestConfigurationFailClosed(t *testing.T) {
	good := map[string]string{"DOCUMENT_BUCKET": "bucket", "STATE_TABLE": "table", "RECEIPT_KEY_ID": "key", "JWT_ISSUER": "https://issuer.example", "ALLOWED_APP_PACKAGE": "io.example.app", "ALLOWED_APP_DIGESTS": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "GOOGLE_ROOTS_PEM": "PEM"}
	get := func(k string) string { return good[k] }
	if _, e := readConfig(get); e != nil {
		t.Fatal(e)
	}
	for _, k := range []string{"JWT_ISSUER", "ALLOWED_APP_PACKAGE", "ALLOWED_APP_DIGESTS", "DOCUMENT_BUCKET", "STATE_TABLE", "RECEIPT_KEY_ID", "GOOGLE_ROOTS_PEM"} {
		old := good[k]
		delete(good, k)
		if _, e := readConfig(get); e == nil {
			t.Fatalf("missing %s accepted", k)
		}
		good[k] = old
	}
	good["JWT_ISSUER"] = "http://issuer.example"
	if _, e := readConfig(get); e == nil {
		t.Fatal("HTTP issuer")
	}
}
