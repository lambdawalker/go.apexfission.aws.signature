package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lambdawalker/go.apexfission.aws.signature/protocol"
)

func (s *Service) CreateChallenge(ctx context.Context, o Identity, r ChallengeRequest) (Challenge, error) {
	var c Challenge
	if !o.Valid() {
		return c, ErrInvalid
	}
	suite, err := protocol.SelectSuite(r.Suites)
	if err != nil {
		return c, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	switch r.Operation {
	case "register":
		if r.KeyID != "" || r.DocumentSHA256 != "" {
			return c, ErrInvalid
		}
	case "sign":
		if !protocol.ValidHash(r.KeyID) || !protocol.ValidHash(r.DocumentSHA256) {
			return c, ErrInvalid
		}
		key, e := s.Store.GetKey(ctx, o, r.KeyID)
		if e != nil {
			return c, e
		}
		if key.Owner != o {
			return c, ErrInvalid
		}
		offered := false
		for _, v := range r.Suites {
			if v == key.Suite {
				offered = true
			}
		}
		if !offered {
			return c, ErrInvalid
		}
		suite = key.Suite
	default:
		return c, ErrInvalid
	}
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return c, err
	}
	id := make([]byte, 32)
	if _, err = rand.Read(id); err != nil {
		return c, err
	}
	now := s.now().Unix()
	c = Challenge{ID: hex.EncodeToString(id), Nonce: nonce, Owner: o, Operation: r.Operation, Suite: suite, KeyID: r.KeyID, DocumentSHA256: r.DocumentSHA256, IssuedAt: now, ExpiresAt: now + 300, Status: "pending"}
	return c, s.Store.PutChallenge(ctx, c)
}
func requestHash(v any) string { b, _ := json.Marshal(v); return protocol.Hash(b) }
func (s *Service) load(ctx context.Context, o Identity, id, op, hash string) (Challenge, error) {
	if !o.Valid() || !protocol.ValidHash(id) {
		return Challenge{}, ErrInvalid
	}
	c, e := s.Store.GetChallenge(ctx, id)
	if e != nil {
		return c, e
	}
	if c.Owner != o || c.Operation != op {
		return c, ErrInvalid
	}
	if c.Status == "pending" {
		if c.ExpiresAt <= s.now().Unix() {
			return c, ErrConflict
		}
	} else if (c.Status != "processing" && c.Status != "complete") || c.RequestHash != hash {
		return c, ErrConflict
	}
	return c, nil
}
func (s *Service) Register(ctx context.Context, o Identity, r RegisterRequest) (Response, error) {
	hash := requestHash(r)
	c, e := s.load(ctx, o, r.ChallengeID, "register", hash)
	if e != nil {
		return Response{}, e
	}
	result, e := s.Attester.Verify(ctx, r.CertificateChain, c.Nonce, c.Suite)
	if e != nil {
		return Response{}, fmt.Errorf("%w: attestation rejected", ErrInvalid)
	}
	statement := c.StatementFor(result.KeyID).Encode()
	if e = protocol.VerifySignature(result.PublicKey, statement, r.Signature); e != nil {
		return Response{}, ErrInvalid
	}
	key := Key{ID: result.KeyID, Owner: o, Suite: c.Suite, CertificateChain: r.CertificateChain, AttestationNonce: c.Nonce, RegistrationID: c.ID}
	return s.commit(ctx, c, hash, statement, r.Signature, nil, key, true)
}
func (s *Service) Sign(ctx context.Context, o Identity, r SignRequest) (Response, error) {
	if len(r.Document) > protocol.MaxDocumentBytes {
		return Response{}, ErrInvalid
	}
	hash := requestHash(r)
	c, e := s.load(ctx, o, r.ChallengeID, "sign", hash)
	if e != nil {
		return Response{}, e
	}
	if protocol.Hash(r.Document) != c.DocumentSHA256 {
		return Response{}, ErrInvalid
	}
	key, e := s.Store.GetKey(ctx, o, c.KeyID)
	if e != nil {
		return Response{}, e
	}
	if key.Owner != o || key.Suite != c.Suite {
		return Response{}, ErrInvalid
	}
	result, e := s.Attester.Verify(ctx, key.CertificateChain, key.AttestationNonce, key.Suite)
	if e != nil {
		return Response{}, fmt.Errorf("%w: registered attestation rejected", ErrInvalid)
	}
	if result.KeyID != c.KeyID {
		return Response{}, ErrInvalid
	}
	statement := c.StatementFor(key.ID).Encode()
	if e = protocol.VerifySignature(result.PublicKey, statement, r.Signature); e != nil {
		return Response{}, ErrInvalid
	}
	return s.commit(ctx, c, hash, statement, r.Signature, r.Document, key, false)
}
func (s *Service) commit(ctx context.Context, c Challenge, hash string, statement, signature, document []byte, key Key, registration bool) (Response, error) {
	if e := s.Store.Claim(ctx, c.ID, hash, s.now().Unix()); e != nil {
		return Response{}, e
	}
	c.RequestHash = hash
	c.Status = "processing"
	raw, e := s.Store.GetEvidence(ctx, c.ID)
	if errors.Is(e, ErrNotFound) {
		payload, err := json.Marshal(Evidence{Version: 1, RequestHash: hash, Challenge: c, Statement: statement, Signature: signature, Document: document, Key: key, VerifiedAt: s.now().Unix(), Policy: "android-hardware-v1"})
		if err != nil {
			return Response{}, err
		}
		digest := sha256.Sum256(payload)
		seal, err := s.Signer.Sign(ctx, digest[:])
		if err != nil {
			return Response{}, err
		}
		env := Envelope{Payload: payload, Seal: seal, Timestamp: Timestamp{Status: "unavailable"}}
		if s.TSA != nil {
			// Timestamp binds payload AND server signature. Fail closed if configured TSA fails.
			sealed, err := json.Marshal(struct {
				Payload json.RawMessage `json:"payload"`
				Seal    Seal            `json:"seal"`
			}{payload, seal})
			if err != nil {
				return Response{}, err
			}
			imprint := sha256.Sum256(sealed)
			token, err := s.TSA.Timestamp(ctx, imprint[:])
			if err != nil {
				return Response{}, err
			}
			if len(token) == 0 {
				return Response{}, errors.New("empty timestamp token")
			}
			env.Timestamp = Timestamp{Status: "verified", Token: token}
		}
		raw, err = json.Marshal(env)
		if err != nil {
			return Response{}, err
		}
		if err = s.Store.PutEvidence(ctx, c.ID, raw); err != nil {
			if !errors.Is(err, ErrConflict) {
				return Response{}, err
			}
			raw, e = s.Store.GetEvidence(ctx, c.ID)
			if e != nil {
				return Response{}, e
			}
		}
	} else if e != nil {
		return Response{}, e
	}
	var envelope Envelope
	if e = json.Unmarshal(raw, &envelope); e != nil {
		return Response{}, e
	}
	var saved Evidence
	if e = json.Unmarshal(envelope.Payload, &saved); e != nil {
		return Response{}, e
	}
	if saved.RequestHash != hash || saved.Challenge.Owner != c.Owner || saved.Challenge.ID != c.ID {
		return Response{}, ErrConflict
	}
	var newKey *Key
	if registration {
		newKey = &key
	}
	if e = s.Store.Complete(ctx, c, newKey); e != nil {
		return Response{}, e
	}
	return Response{EvidenceID: c.ID, KeyID: key.ID, TimestampStatus: envelope.Timestamp.Status}, nil
}
