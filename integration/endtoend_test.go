package integration_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/lambdawalker/go.apexfission.aws.signature/attestation"
	"github.com/lambdawalker/go.apexfission.aws.signature/protocol"
	"github.com/lambdawalker/go.apexfission.aws.signature/service"
)

// These tests exercise the real service, protocol and attestation verifier. Only
// persistence, the revocation network boundary and receipt key custody are local.
func TestHardwareRegistrationAndDocumentSigning(t *testing.T) {
	for _, suite := range []string{protocol.TEE, protocol.StrongBox} {
		t.Run(suite, func(t *testing.T) {
			ctx := context.Background()
			now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
			owner := service.Identity{Issuer: "https://identity.example", Subject: "account-42"}
			store := newMemoryStore()
			receiptKey := newKey(t)
			revocations := &checkedRevocations{}
			signerDigest := sha256.Sum256([]byte("test APK signer certificate"))
			s := &service.Service{Store: store, Signer: receiptSigner{receiptKey}, Now: func() time.Time { return now }}
			challenge, err := s.CreateChallenge(ctx, owner, service.ChallengeRequest{Operation: "register", Suites: []string{suite}})
			if err != nil {
				t.Fatal(err)
			}
			chain, roots, key := hardwareChain(t, now, challenge.Nonce, suite, "example.swornink", signerDigest[:])
			s.Attester = &attestation.Verifier{Policy: attestation.Policy{Roots: roots, AppPackage: "example.swornink", AppSignerDigests: [][]byte{signerDigest[:]}, Now: func() time.Time { return now }, Revocations: revocations}}
			leaf, err := x509.ParseCertificate(chain[0])
			if err != nil {
				t.Fatal(err)
			}
			keyID := protocol.Hash(leaf.RawSubjectPublicKeyInfo)
			statement := challenge.StatementFor(keyID).Encode()
			registration := service.RegisterRequest{ChallengeID: challenge.ID, CertificateChain: chain, Signature: signStatement(t, key, statement)}
			tampered := registration
			tampered.Signature = append([]byte(nil), registration.Signature...)
			tampered.Signature[len(tampered.Signature)-1] ^= 1
			if _, err = s.Register(ctx, owner, tampered); !errors.Is(err, service.ErrInvalid) {
				t.Fatalf("tampered registration signature accepted: %v", err)
			}
			assertPending(t, store, challenge.ID)
			registered, err := s.Register(ctx, owner, registration)
			if err != nil {
				t.Fatal(err)
			}
			if registered.KeyID != keyID || registered.EvidenceID != challenge.ID {
				t.Fatalf("incorrect registration response: %+v", registered)
			}
			stored, err := store.GetKey(ctx, owner, keyID)
			if err != nil {
				t.Fatal(err)
			}
			if stored.Suite != suite || !bytes.Equal(stored.AttestationNonce, challenge.Nonce) {
				t.Fatal("stored registration binding changed")
			}
			verifyEvidence(t, store, registered.EvidenceID, receiptKey, statement, nil)
			document := []byte("Signed agreement: transfer one blue notebook.")
			signChallenge, err := s.CreateChallenge(ctx, owner, service.ChallengeRequest{Operation: "sign", Suites: []string{suite}, KeyID: keyID, DocumentSHA256: protocol.Hash(document)})
			if err != nil {
				t.Fatal(err)
			}
			signStatementBytes := signChallenge.StatementFor(keyID).Encode()
			request := service.SignRequest{ChallengeID: signChallenge.ID, Document: document, Signature: signStatement(t, key, signStatementBytes)}
			invalid := request
			invalid.Signature = append([]byte(nil), request.Signature...)
			invalid.Signature[len(invalid.Signature)-1] ^= 1
			if _, err = s.Sign(ctx, owner, invalid); !errors.Is(err, service.ErrInvalid) {
				t.Fatalf("tampered document signature accepted: %v", err)
			}
			assertPending(t, store, signChallenge.ID)
			invalid = request
			invalid.Document = []byte("Changed agreement")
			if _, err = s.Sign(ctx, owner, invalid); !errors.Is(err, service.ErrInvalid) {
				t.Fatalf("tampered document accepted: %v", err)
			}
			signed, err := s.Sign(ctx, owner, request)
			if err != nil {
				t.Fatal(err)
			}
			if signed.KeyID != keyID || signed.TimestampStatus != "unavailable" {
				t.Fatalf("incorrect signing response: %+v", signed)
			}
			verifyEvidence(t, store, signed.EvidenceID, receiptKey, signStatementBytes, document)
			if revocations.calls < 4 {
				t.Fatalf("expected real attestation checks at registration and signing, got %d", revocations.calls)
			}
		})
	}
}

func TestRegistrationRejectsAttestedIdentityOrChallengeMismatch(t *testing.T) {
	for _, failure := range []string{"wrong package", "wrong nonce", "wrong signer"} {
		t.Run(failure, func(t *testing.T) {
			ctx := context.Background()
			now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
			owner := service.Identity{Issuer: "https://identity.example", Subject: "account-42"}
			store := newMemoryStore()
			s := &service.Service{Store: store, Signer: receiptSigner{newKey(t)}, Now: func() time.Time { return now }}
			challenge, err := s.CreateChallenge(ctx, owner, service.ChallengeRequest{Operation: "register", Suites: []string{protocol.TEE}})
			if err != nil {
				t.Fatal(err)
			}
			nonce := append([]byte(nil), challenge.Nonce...)
			pkg := "example.swornink"
			allowed := sha256.Sum256([]byte("expected signer"))
			presented := allowed[:]
			switch failure {
			case "wrong package":
				pkg = "example.impostor"
			case "wrong nonce":
				nonce[0] ^= 1
			case "wrong signer":
				other := sha256.Sum256([]byte("impostor signer"))
				presented = other[:]
			}
			chain, roots, key := hardwareChain(t, now, nonce, protocol.TEE, pkg, presented)
			s.Attester = &attestation.Verifier{Policy: attestation.Policy{Roots: roots, AppPackage: "example.swornink", AppSignerDigests: [][]byte{allowed[:]}, Now: func() time.Time { return now }, Revocations: &checkedRevocations{}}}
			leaf, _ := x509.ParseCertificate(chain[0])
			keyID := protocol.Hash(leaf.RawSubjectPublicKeyInfo)
			request := service.RegisterRequest{ChallengeID: challenge.ID, CertificateChain: chain, Signature: signStatement(t, key, challenge.StatementFor(keyID).Encode())}
			if _, err = s.Register(ctx, owner, request); !errors.Is(err, service.ErrInvalid) {
				t.Fatalf("invalid attestation accepted: %v", err)
			}
			assertPending(t, store, challenge.ID)
			if _, err = store.GetKey(ctx, owner, keyID); !errors.Is(err, service.ErrNotFound) {
				t.Fatal("rejected registration persisted a key")
			}
		})
	}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func signStatement(t *testing.T, key *ecdsa.PrivateKey, statement []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(statement)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}
func marshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
func container(tag int, fields ...[]byte) []byte {
	var b []byte
	for _, f := range fields {
		b = append(b, f...)
	}
	return marshal(asn1.RawValue{Tag: tag, IsCompound: true, Bytes: b})
}
func tagged(tag int, inner []byte) []byte {
	return marshal(asn1.RawValue{Class: 2, Tag: tag, IsCompound: true, Bytes: inner})
}
func hardwareChain(t *testing.T, now time.Time, nonce []byte, suite, pkg string, signer []byte) ([][]byte, *x509.CertPool, *ecdsa.PrivateKey) {
	t.Helper()
	rootKey := newKey(t)
	key := newKey(t)
	root := &x509.Certificate{SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "integration-only hardware root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	level := 1
	if suite == protocol.StrongBox {
		level = 2
	}
	app := container(16, container(17, container(16, marshal([]byte(pkg)), marshal(1))), container(17, marshal(signer)))
	boot := container(16, marshal(bytes.Repeat([]byte{1}, 32)), marshal(true), marshal(asn1.Enumerated(0)), marshal(bytes.Repeat([]byte{2}, 32)))
	hardware := container(16, tagged(1, container(17, marshal(2))), tagged(2, marshal(3)), tagged(3, marshal(256)), tagged(5, container(17, marshal(4))), tagged(10, marshal(1)), tagged(504, marshal(2)), tagged(702, marshal(0)), tagged(704, boot))
	extension := container(16, marshal(3), marshal(asn1.Enumerated(level)), marshal(4), marshal(asn1.Enumerated(level)), marshal(nonce), marshal([]byte{}), container(16, tagged(709, marshal(app))), hardware)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "integration hardware signing key"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}, Value: extension}}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return [][]byte{leafDER, rootDER}, roots, key
}

type checkedRevocations struct{ calls int }

func (c *checkedRevocations) Check(_ context.Context, chain []*x509.Certificate) error {
	if len(chain) != 2 || chain[0].SerialNumber.Int64() != 101 || chain[1].SerialNumber.Int64() != 100 {
		return errors.New("incorrect verified revocation path")
	}
	c.calls++
	return nil
}

type receiptSigner struct{ key *ecdsa.PrivateKey }

func (s receiptSigner) Sign(_ context.Context, digest []byte) (service.Seal, error) {
	signature, err := ecdsa.SignASN1(rand.Reader, s.key, digest)
	if err != nil {
		return service.Seal{}, err
	}
	public, err := x509.MarshalPKIXPublicKey(&s.key.PublicKey)
	return service.Seal{Algorithm: "ECDSA_SHA_256", KeyID: "local-integration-receipt-key", PublicKeyDER: public, Signature: signature}, err
}
func verifyEvidence(t *testing.T, store *memoryStore, id string, key *ecdsa.PrivateKey, statement, document []byte) {
	t.Helper()
	raw, err := store.GetEvidence(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	var envelope service.Envelope
	if err = json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(envelope.Payload)
	if !ecdsa.VerifyASN1(&key.PublicKey, hash[:], envelope.Seal.Signature) {
		t.Fatal("receipt does not sign the exact evidence payload digest")
	}
	public, err := x509.ParsePKIXPublicKey(envelope.Seal.PublicKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	if !public.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatal("receipt public key changed")
	}
	var evidence service.Evidence
	if err = json.Unmarshal(envelope.Payload, &evidence); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(evidence.Statement, statement) || !bytes.Equal(evidence.Document, document) || envelope.Timestamp.Status != "unavailable" {
		t.Fatal("evidence contents differ from signed operation")
	}
	leaf, err := x509.ParseCertificate(evidence.Key.CertificateChain[0])
	if err != nil {
		t.Fatal(err)
	}
	if err = protocol.VerifySignature(leaf.PublicKey.(*ecdsa.PublicKey), evidence.Statement, evidence.Signature); err != nil {
		t.Fatal("saved client signature is invalid", err)
	}
	challenge, err := store.GetChallenge(context.Background(), id)
	if err != nil || challenge.Status != "complete" {
		t.Fatal("verified operation not complete", err)
	}
}
func assertPending(t *testing.T, store *memoryStore, id string) {
	t.Helper()
	challenge, err := store.GetChallenge(context.Background(), id)
	if err != nil || challenge.Status != "pending" {
		t.Fatal("rejected request consumed challenge", err)
	}
	if _, err = store.GetEvidence(context.Background(), id); !errors.Is(err, service.ErrNotFound) {
		t.Fatal("rejected request created evidence")
	}
}

type memoryStore struct {
	mu         sync.Mutex
	challenges map[string]service.Challenge
	keys       map[string]service.Key
	evidence   map[string][]byte
}

func newMemoryStore() *memoryStore {
	return &memoryStore{challenges: map[string]service.Challenge{}, keys: map[string]service.Key{}, evidence: map[string][]byte{}}
}
func (m *memoryStore) PutChallenge(_ context.Context, c service.Challenge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.challenges[c.ID]; exists {
		return service.ErrConflict
	}
	m.challenges[c.ID] = c
	return nil
}
func (m *memoryStore) GetChallenge(_ context.Context, id string) (service.Challenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.challenges[id]
	if !ok {
		return c, service.ErrNotFound
	}
	return c, nil
}
func (m *memoryStore) GetKey(_ context.Context, o service.Identity, id string) (service.Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[o.ID()+id]
	if !ok {
		return k, service.ErrNotFound
	}
	return k, nil
}
func (m *memoryStore) Claim(_ context.Context, id, hash string, now int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.challenges[id]
	if !ok {
		return service.ErrNotFound
	}
	if c.Status == "pending" && c.ExpiresAt > now {
		c.Status = "processing"
		c.RequestHash = hash
		m.challenges[id] = c
		return nil
	}
	if c.RequestHash == hash && (c.Status == "processing" || c.Status == "complete") {
		return nil
	}
	return service.ErrConflict
}
func (m *memoryStore) Complete(_ context.Context, c service.Challenge, k *service.Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	saved, ok := m.challenges[c.ID]
	if !ok || saved.RequestHash != c.RequestHash || saved.Owner != c.Owner {
		return service.ErrConflict
	}
	if k != nil {
		m.keys[k.Owner.ID()+k.ID] = *k
	}
	saved.Status = "complete"
	m.challenges[c.ID] = saved
	return nil
}
func (m *memoryStore) GetEvidence(_ context.Context, id string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	raw, ok := m.evidence[id]
	if !ok {
		return nil, service.ErrNotFound
	}
	return append([]byte(nil), raw...), nil
}
func (m *memoryStore) PutEvidence(_ context.Context, id string, raw []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.evidence[id]; exists {
		return service.ErrConflict
	}
	m.evidence[id] = append([]byte(nil), raw...)
	return nil
}
