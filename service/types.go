// Package service implements authenticated challenge registration and signing.
package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/lambdawalker/go.apexfission.aws.signature/attestation"
	"github.com/lambdawalker/go.apexfission.aws.signature/protocol"
	"time"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("operation conflict")
	ErrInvalid  = errors.New("invalid request")
)

type Identity struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

func (o Identity) ID() string {
	return protocol.Hash(protocol.Statement{Issuer: o.Issuer, Subject: o.Subject}.Encode())
}
func (o Identity) Valid() bool {
	return o.Issuer != "" && o.Subject != "" && len(o.Issuer) <= 2048 && len(o.Subject) <= 512
}

type Challenge struct {
	ID             string   `json:"challengeId"`
	Nonce          []byte   `json:"nonce"`
	Owner          Identity `json:"owner"`
	Operation      string   `json:"operation"`
	Suite          string   `json:"suite"`
	KeyID          string   `json:"keyId"`
	DocumentSHA256 string   `json:"documentSHA256"`
	IssuedAt       int64    `json:"issuedAt"`
	ExpiresAt      int64    `json:"expiresAt"`
	Status         string   `json:"status"`
	RequestHash    string   `json:"-"`
}

func (c Challenge) StatementFor(keyID string) protocol.Statement {
	return protocol.Statement{Operation: c.Operation, Suite: c.Suite, ChallengeID: c.ID, Nonce: base64.StdEncoding.EncodeToString(c.Nonce), Issuer: c.Owner.Issuer, Subject: c.Owner.Subject, KeyID: keyID, DocumentSHA256: c.DocumentSHA256}
}

type ChallengeRequest struct {
	Operation      string   `json:"operation"`
	Suites         []string `json:"suites"`
	KeyID          string   `json:"keyId"`
	DocumentSHA256 string   `json:"documentSHA256"`
}
type RegisterRequest struct {
	ChallengeID      string   `json:"challengeId"`
	CertificateChain [][]byte `json:"certificateChain"`
	Signature        []byte   `json:"signature"`
}
type SignRequest struct {
	ChallengeID string `json:"challengeId"`
	Document    []byte `json:"document"`
	Signature   []byte `json:"signature"`
}
type Key struct {
	ID               string   `json:"keyId"`
	Owner            Identity `json:"owner"`
	Suite            string   `json:"suite"`
	CertificateChain [][]byte `json:"certificateChain"`
	AttestationNonce []byte   `json:"attestationNonce"`
	RegistrationID   string   `json:"registrationId"`
}
type Seal struct {
	Algorithm    string `json:"algorithm"`
	KeyID        string `json:"keyId"`
	PublicKeyDER []byte `json:"publicKeyDER"`
	Signature    []byte `json:"signature"`
}

// Timestamp providers MUST validate TSA trust, imprint, policy, nonce and time before returning a token.
type TimestampProvider interface {
	Timestamp(context.Context, []byte) ([]byte, error)
}
type Timestamp struct {
	Status string `json:"status"`
	Token  []byte `json:"token,omitempty"`
}
type Evidence struct {
	Version     int       `json:"version"`
	RequestHash string    `json:"requestHash"`
	Challenge   Challenge `json:"challenge"`
	Statement   []byte    `json:"statement"`
	Signature   []byte    `json:"signature"`
	Document    []byte    `json:"document,omitempty"`
	Key         Key       `json:"key"`
	VerifiedAt  int64     `json:"verifiedAt"`
	Policy      string    `json:"policy"`
}
type Envelope struct {
	Payload   json.RawMessage `json:"payload"`
	Seal      Seal            `json:"seal"`
	Timestamp Timestamp       `json:"timestamp"`
}
type Response struct {
	EvidenceID      string `json:"evidenceId"`
	KeyID           string `json:"keyId"`
	TimestampStatus string `json:"timestampStatus"`
}
type Store interface {
	PutChallenge(context.Context, Challenge) error
	GetChallenge(context.Context, string) (Challenge, error)
	GetKey(context.Context, Identity, string) (Key, error)
	Claim(context.Context, string, string, int64) error
	Complete(context.Context, Challenge, *Key) error
	GetEvidence(context.Context, string) ([]byte, error)
	PutEvidence(context.Context, string, []byte) error
}
type Attester interface {
	Verify(context.Context, [][]byte, []byte, string) (*attestation.Result, error)
}
type Signer interface {
	Sign(context.Context, []byte) (Seal, error)
}

// Service has no owned goroutines. Dependencies must support concurrent calls.
// Configure once before serving; Now is injectable for expiry tests.
type Service struct {
	Store    Store
	Attester Attester
	Signer   Signer
	TSA      TimestampProvider
	Now      func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
