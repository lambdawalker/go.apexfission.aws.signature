package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"github.com/lambdawalker/go.apexfission.aws.signature/attestation"
	"github.com/lambdawalker/go.apexfission.aws.signature/protocol"
	"sync"
	"testing"
	"time"
)

type memory struct {
	mu   sync.Mutex
	c    map[string]Challenge
	k    map[string]Key
	e    map[string][]byte
	fail bool
}

func newMemory() *memory {
	return &memory{c: map[string]Challenge{}, k: map[string]Key{}, e: map[string][]byte{}}
}
func (m *memory) PutChallenge(_ context.Context, c Challenge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.c[c.ID] = c
	return nil
}
func (m *memory) GetChallenge(_ context.Context, id string) (Challenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.c[id]
	if !ok {
		return c, ErrNotFound
	}
	return c, nil
}
func (m *memory) GetKey(_ context.Context, o Identity, id string) (Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.k[o.ID()+id]
	if !ok {
		return k, ErrNotFound
	}
	return k, nil
}
func (m *memory) Claim(_ context.Context, id, hash string, now int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.c[id]
	if c.Status == "pending" && c.ExpiresAt > now {
		c.Status = "processing"
		c.RequestHash = hash
		m.c[id] = c
		return nil
	}
	if c.RequestHash == hash && (c.Status == "processing" || c.Status == "complete") {
		return nil
	}
	return ErrConflict
}
func (m *memory) Complete(_ context.Context, c Challenge, k *Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.c[c.ID]
	if old.RequestHash != c.RequestHash {
		return ErrConflict
	}
	if k != nil {
		m.k[k.Owner.ID()+k.ID] = *k
	}
	old.Status = "complete"
	m.c[c.ID] = old
	return nil
}
func (m *memory) GetEvidence(_ context.Context, id string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.e[id]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), v...), nil
}
func (m *memory) PutEvidence(_ context.Context, id string, b []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("S3 unavailable")
	}
	if _, ok := m.e[id]; ok {
		return ErrConflict
	}
	m.e[id] = append([]byte(nil), b...)
	return nil
}

type acceptAttestation struct{ key *ecdsa.PublicKey }

func (a acceptAttestation) Verify(_ context.Context, _ [][]byte, _ []byte, _ string) (*attestation.Result, error) {
	return &attestation.Result{PublicKey: a.key, KeyID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, nil
}

type localSigner struct{}

func (localSigner) Sign(_ context.Context, b []byte) (Seal, error) {
	return Seal{Algorithm: "test-only", Signature: b}, nil
}
func fixture(t *testing.T) (*Service, *memory, *ecdsa.PrivateKey, Identity) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	m := newMemory()
	s := &Service{Store: m, Attester: acceptAttestation{&key.PublicKey}, Signer: localSigner{}, Now: func() time.Time { return time.Unix(1000, 0) }}
	return s, m, key, Identity{Issuer: "https://issuer", Subject: "alice"}
}
func sig(k *ecdsa.PrivateKey, b []byte) []byte {
	h := sha256.Sum256(b)
	s, _ := ecdsa.SignASN1(rand.Reader, k, h[:])
	return s
}
func register(t *testing.T, s *Service, k *ecdsa.PrivateKey, o Identity) (Key, Response) {
	t.Helper()
	c, e := s.CreateChallenge(context.Background(), o, ChallengeRequest{Operation: "register", Suites: []string{protocol.TEE}})
	if e != nil {
		t.Fatal(e)
	}
	st := c.StatementFor("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	r, e := s.Register(context.Background(), o, RegisterRequest{ChallengeID: c.ID, CertificateChain: [][]byte{{1}}, Signature: sig(k, st.Encode())})
	if e != nil {
		t.Fatal(e)
	}
	return Key{ID: st.KeyID}, r
}
func TestRegistrationAndCrossAccount(t *testing.T) {
	s, _, k, o := fixture(t)
	c, _ := s.CreateChallenge(context.Background(), o, ChallengeRequest{Operation: "register", Suites: []string{protocol.TEE}})
	req := RegisterRequest{ChallengeID: c.ID, CertificateChain: [][]byte{{1}}, Signature: sig(k, c.StatementFor("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").Encode())}
	other := o
	other.Subject = "bob"
	if _, e := s.Register(context.Background(), other, req); e == nil {
		t.Fatal("cross-account accepted")
	}
	if _, e := s.Register(context.Background(), o, req); e != nil {
		t.Fatal(e)
	}
}
func TestExpiredChallenge(t *testing.T) {
	s, _, k, o := fixture(t)
	c, _ := s.CreateChallenge(context.Background(), o, ChallengeRequest{Operation: "register", Suites: []string{protocol.TEE}})
	s.Now = func() time.Time { return time.Unix(c.ExpiresAt, 0) }
	_, e := s.Register(context.Background(), o, RegisterRequest{ChallengeID: c.ID, Signature: sig(k, nil)})
	if e == nil {
		t.Fatal("expired accepted")
	}
}
func TestSigningMutationRetryAndS3Failure(t *testing.T) {
	s, m, k, o := fixture(t)
	key, _ := register(t, s, k, o)
	doc := []byte("contract")
	c, e := s.CreateChallenge(context.Background(), o, ChallengeRequest{Operation: "sign", Suites: []string{protocol.TEE}, KeyID: key.ID, DocumentSHA256: protocol.Hash(doc)})
	if e != nil {
		t.Fatal(e)
	}
	r := SignRequest{ChallengeID: c.ID, Document: doc, Signature: sig(k, c.StatementFor(key.ID).Encode())}
	bad := r
	bad.Document = []byte("tampered")
	if _, e = s.Sign(context.Background(), o, bad); e == nil {
		t.Fatal("tamper accepted")
	}
	m.fail = true
	if _, e = s.Sign(context.Background(), o, r); e == nil {
		t.Fatal("S3 failure reported success")
	}
	if m.c[c.ID].Status == "complete" {
		t.Fatal("premature completion")
	}
	m.fail = false
	a, e := s.Sign(context.Background(), o, r)
	if e != nil {
		t.Fatal(e)
	}
	b, e := s.Sign(context.Background(), o, r)
	if e != nil || a.EvidenceID != b.EvidenceID {
		t.Fatal("retry not idempotent", e)
	}
	bad = r
	bad.Signature = sig(k, c.StatementFor(key.ID).Encode())
	if _, e = s.Sign(context.Background(), o, bad); e == nil {
		t.Fatal("replacement accepted")
	}
}
func TestSuiteCannotDowngradeExistingKey(t *testing.T) {
	s, m, k, o := fixture(t)
	key, _ := register(t, s, k, o)
	stored := m.k[o.ID()+key.ID]
	stored.Suite = protocol.StrongBox
	m.k[o.ID()+key.ID] = stored
	if _, e := s.CreateChallenge(context.Background(), o, ChallengeRequest{Operation: "sign", Suites: []string{protocol.TEE}, KeyID: key.ID, DocumentSHA256: protocol.Hash(nil)}); e == nil {
		t.Fatal("downgraded")
	}
}
func TestMissingIdentityAndUnsupportedOperation(t *testing.T) {
	s, _, _, o := fixture(t)
	for _, r := range []ChallengeRequest{{Operation: "register", Suites: []string{"software"}}, {Operation: "delete", Suites: []string{protocol.TEE}}} {
		if _, e := s.CreateChallenge(context.Background(), o, r); e == nil {
			t.Fatal("accepted invalid")
		}
	}
	if _, e := s.CreateChallenge(context.Background(), Identity{}, ChallengeRequest{Operation: "register", Suites: []string{protocol.TEE}}); e == nil {
		t.Fatal("anonymous")
	}
}
