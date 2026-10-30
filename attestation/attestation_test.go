package attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
var testNonce = make([]byte, 32)
var signer = sha256.Sum256([]byte("signer"))

func der(v any) []byte {
	b, e := asn1.Marshal(v)
	if e != nil {
		panic(e)
	}
	return b
}
func raw(tag int, children ...[]byte) []byte {
	var b []byte
	for _, c := range children {
		b = append(b, c...)
	}
	return der(asn1.RawValue{Class: 0, Tag: tag, IsCompound: tag == 16 || tag == 17, Bytes: b})
}
func tagged(tag int, b []byte) []byte {
	return der(asn1.RawValue{Class: 2, Tag: tag, IsCompound: true, Bytes: b})
}
func integer(v int) []byte { return der(v) }
func oct(v []byte) []byte  { return der(v) }
func application(pkg string, digest []byte) []byte {
	return oct(raw(16, raw(17, raw(16, oct([]byte(pkg)), integer(1))), raw(17, oct(digest))))
}
func hw() [][]byte {
	return [][]byte{tagged(1, raw(17, integer(2))), tagged(2, integer(3)), tagged(3, integer(256)), tagged(5, raw(17, integer(4))), tagged(10, integer(1)), tagged(504, integer(2)), tagged(702, integer(0)), tagged(704, raw(16, oct(make([]byte, 32)), der(true), der(asn1.Enumerated(0)), oct(make([]byte, 32))))}
}
func record(sw, hardware [][]byte, level int, nonce []byte) []byte {
	return raw(16, integer(3), der(asn1.Enumerated(level)), integer(4), der(asn1.Enumerated(level)), oct(nonce), oct(nil), raw(16, sw...), raw(16, hardware...))
}
func fixture(t *testing.T, extension []byte) ([][]byte, *x509.CertPool, *x509.Certificate) {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, e := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if e != nil {
		t.Fatal(e)
	}
	root, e = x509.ParseCertificate(rootDER)
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}, Value: extension}}}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, root, &leafKey.PublicKey, rootKey)
	if e != nil {
		t.Fatal(e)
	}
	leaf, _ = x509.ParseCertificate(leafDER)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return [][]byte{leafDER, rootDER}, roots, leaf
}

type checkFunc func(context.Context, []*x509.Certificate) error

func (f checkFunc) Check(c context.Context, chain []*x509.Certificate) error { return f(c, chain) }
func policy(roots *x509.CertPool) Policy {
	return Policy{Roots: roots, AppPackage: "test.app", AppSignerDigests: [][]byte{signer[:]}, Now: func() time.Time { return testNow }, Revocations: checkFunc(func(_ context.Context, c []*x509.Certificate) error {
		if len(c) != 2 {
			return errors.New("missing root revocation")
		}
		return nil
	})}
}
func TestVerifyHardwareAndPolicy(t *testing.T) {
	for _, level := range []int{1, 2} {
		suite := "ES256_TEE"
		if level == 2 {
			suite = "ES256_STRONGBOX"
		}
		chain, roots, leaf := fixture(t, record([][]byte{tagged(709, application("test.app", signer[:]))}, hw(), level, testNonce))
		v := Verifier{Policy: policy(roots)}
		got, e := v.Verify(context.Background(), chain, testNonce, suite)
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		if got.KeyID != hex.EncodeToString(sum[:]) || got.PublicKey == nil {
			t.Fatal("incorrect key binding")
		}
	}
}
func TestRejectAttestationPolicyViolations(t *testing.T) {
	sw := [][]byte{tagged(709, application("test.app", signer[:]))}
	cases := map[string][]byte{
		"software": record(sw, hw(), 0, testNonce), "wrong challenge": record(sw, hw(), 1, []byte("wrong")), "timeout": record(sw, append(hw(), tagged(505, integer(0))), 1, testNonce), "no auth": record(sw, append(hw(), tagged(503, []byte{5, 0})), 1, testNonce), "all apps": record(sw, append(hw(), tagged(600, []byte{5, 0})), 1, testNonce), "duplicate": record(sw, append(hw(), tagged(504, integer(2))), 1, testNonce), "package": record([][]byte{tagged(709, application("evil", signer[:]))}, hw(), 1, testNonce), "signer": record([][]byte{tagged(709, application("test.app", make([]byte, 32)))}, hw(), 1, testNonce), "software authorization": record(append(sw, tagged(504, integer(2))), hw(), 1, testNonce), "truncated": {0x30, 0x82, 0x10}, "trailing": append(record(sw, hw(), 1, testNonce), 0), "malformed explicit": record(sw, append(hw(), tagged(999, []byte{2, 2, 1})), 1, testNonce),
	}
	for name, ext := range cases {
		t.Run(name, func(t *testing.T) {
			chain, roots, _ := fixture(t, ext)
			v := Verifier{Policy: policy(roots)}
			if _, e := v.Verify(context.Background(), chain, testNonce, "ES256_TEE"); e == nil {
				t.Fatal("accepted invalid attestation")
			}
		})
	}
}
func TestRejectTrustRevocationAndSuite(t *testing.T) {
	chain, roots, _ := fixture(t, record([][]byte{tagged(709, application("test.app", signer[:]))}, hw(), 1, testNonce))
	for _, name := range []string{"untrusted", "expired", "no revocations", "revoked", "suite", "nil roots"} {
		t.Run(name, func(t *testing.T) {
			p := policy(roots)
			suite := "ES256_TEE"
			switch name {
			case "untrusted":
				p.Roots = x509.NewCertPool()
			case "expired":
				p.Now = func() time.Time { return testNow.Add(24 * time.Hour) }
			case "no revocations":
				p.Revocations = nil
			case "revoked":
				p.Revocations = checkFunc(func(context.Context, []*x509.Certificate) error { return errors.New("revoked") })
			case "suite":
				suite = "ES256_STRONGBOX"
			case "nil roots":
				p.Roots = nil
			}
			if _, e := (&Verifier{Policy: p}).Verify(context.Background(), chain, testNonce, suite); e == nil {
				t.Fatal("accepted invalid trust policy")
			}
		})
	}
}

func TestRejectHardwareMutation(t *testing.T) {
	mutations := []struct {
		name        string
		tag         int
		replacement []byte
	}{
		{"password auth", 504, tagged(504, integer(1))}, {"any auth", 504, tagged(504, integer(3))},
		{"imported key", 702, tagged(702, integer(2))}, {"wrong curve", 10, tagged(10, integer(2))},
		{"wrong digest", 5, tagged(5, raw(17, integer(0)))}, {"extra digest", 5, tagged(5, raw(17, integer(0), integer(4)))},
		{"verify purpose", 1, tagged(1, raw(17, integer(3)))}, {"duplicate purpose", 1, tagged(1, raw(17, integer(2), integer(2)))},
		{"unlocked", 704, tagged(704, raw(16, oct(make([]byte, 32)), der(false), der(asn1.Enumerated(0)), oct(make([]byte, 32))))},
		{"unverified boot", 704, tagged(704, raw(16, oct(make([]byte, 32)), der(true), der(asn1.Enumerated(2)), oct(make([]byte, 32))))},
		{"missing origin", 702, nil}, {"missing biometric", 504, nil}, {"wrong algorithm", 2, tagged(2, integer(1))},
		{"noncanonical integer", 504, tagged(504, []byte{2, 2, 0, 2})}, {"negative integer", 504, tagged(504, []byte{2, 1, 0xff})},
	}
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			fields := hw()
			var next [][]byte
			for _, f := range fields {
				var x asn1.RawValue
				if _, e := asn1.Unmarshal(f, &x); e != nil {
					t.Fatal(e)
				}
				if x.Tag == m.tag {
					if m.replacement != nil {
						next = append(next, m.replacement)
					}
				} else {
					next = append(next, f)
				}
			}
			chain, roots, _ := fixture(t, record([][]byte{tagged(709, application("test.app", signer[:]))}, next, 1, testNonce))
			if _, e := (&Verifier{Policy: policy(roots)}).Verify(context.Background(), chain, testNonce, "ES256_TEE"); e == nil {
				t.Fatal("accepted invalid hardware policy")
			}
		})
	}
}
func TestEveryTruncationFails(t *testing.T) {
	ext := record([][]byte{tagged(709, application("test.app", signer[:]))}, hw(), 1, testNonce)
	for i := 0; i < len(ext); i++ {
		if _, e := parseRecord(ext[:i], testNonce, 1, policy(x509.NewCertPool())); e == nil {
			t.Fatalf("accepted truncation %d", i)
		}
	}
}
func TestBoundedChainInputs(t *testing.T) {
	v := Verifier{Policy: policy(x509.NewCertPool())}
	for _, chain := range [][][]byte{nil, make([][]byte, 9), {make([]byte, 65537), {1}}} {
		if _, e := v.Verify(context.Background(), chain, testNonce, "ES256_TEE"); e == nil {
			t.Fatal("accepted bounded input")
		}
	}
}
func FuzzAttestationDER(f *testing.F) {
	f.Add(record([][]byte{tagged(709, application("test.app", signer[:]))}, hw(), 1, testNonce))
	f.Add([]byte{0x30, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 32<<10 {
			return
		}
		_, _ = parseRecord(b, testNonce, 1, policy(x509.NewCertPool()))
	})
}
