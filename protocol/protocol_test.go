package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestSelectSuitePolicyOrder(t *testing.T) {
	s, e := SelectSuite([]string{TEE, StrongBox})
	if e != nil || s != StrongBox {
		t.Fatalf("got %q %v", s, e)
	}
	if _, e = SelectSuite([]string{"RSA1024"}); e == nil {
		t.Fatal("accepted unsupported")
	}
}
func TestStatementLengthDelimited(t *testing.T) {
	s := Statement{Operation: "register", Suite: StrongBox, ChallengeID: "id", Nonce: "nonce", Issuer: "iss", Subject: "sub", KeyID: "key"}
	b := s.Encode()
	if hex.EncodeToString(b[:16]) != "0000000c73776f726e2d696e6b2f7631" {
		t.Fatalf("bad domain encoding %x", b)
	}
	other := s
	other.Issuer = "is"
	other.Subject = "ssub"
	if string(b) == string(other.Encode()) {
		t.Fatal("ambiguous encoding")
	}
}
func TestVerifySignatureRejectsMutationsAndDoubleHash(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	msg := []byte("statement")
	h := sha256.Sum256(msg)
	sig, _ := ecdsa.SignASN1(rand.Reader, k, h[:])
	if err := VerifySignature(&k.PublicKey, msg, sig); err != nil {
		t.Fatal(err)
	}
	if VerifySignature(&k.PublicKey, []byte("changed"), sig) == nil {
		t.Fatal("accepted mutation")
	}
	if VerifySignature(&k.PublicKey, h[:], sig) == nil {
		t.Fatal("accepted double hash")
	}
	if VerifySignature(nil, msg, sig) == nil {
		t.Fatal("accepted nil key")
	}
}
func TestHashValidation(t *testing.T) {
	for _, s := range []string{"", "AA", "zz"} {
		if ValidHash(s) {
			t.Fatalf("accepted %q", s)
		}
	}
	if !ValidHash(string(makeHex())) {
		t.Fatal("rejected valid")
	}
}
func makeHex() []byte {
	return []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
}

func TestAndroidSharedVector(t *testing.T) {
	b, e := os.ReadFile("test-vectors/v1.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Fields     []string `json:"fields"`
		EncodedHex string   `json:"encodedHex"`
	}
	if json.Unmarshal(b, &v) != nil || len(v.Fields) != 9 {
		t.Fatal("invalid vector")
	}
	f := v.Fields
	s := Statement{Operation: f[1], Suite: f[2], ChallengeID: f[3], Nonce: f[4], Issuer: f[5], Subject: f[6], KeyID: f[7], DocumentSHA256: f[8]}
	if hex.EncodeToString(s.Encode()) != v.EncodedHex {
		t.Fatal("Android/Go encoding mismatch")
	}
}

func TestVerifyDocumentHashIsPrehashed(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h := sha256.Sum256([]byte("contract"))
	signature, _ := ecdsa.SignASN1(rand.Reader, k, h[:])
	if err := VerifyDocumentHash(&k.PublicKey, h[:], signature); err != nil {
		t.Fatal("digest must be verified directly", err)
	}
	if VerifyDocumentHash(&k.PublicKey, h[:31], signature) == nil {
		t.Fatal("accepted truncated digest")
	}
}
