// Package protocol defines the versioned Android/Go signing contract.
package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

const (
	StrongBox        = "ES256_STRONGBOX"
	TEE              = "ES256_TEE"
	MaxDocumentBytes = 512 * 1024
)

// SelectSuite applies server policy, ignoring client order and unknown suites.
func SelectSuite(offered []string) (string, error) {
	if len(offered) > 16 {
		return "", errors.New("too many suites")
	}
	for _, s := range []string{StrongBox, TEE} {
		for _, o := range offered {
			if o == s {
				return s, nil
			}
		}
	}
	return "", errors.New("no permitted hardware signing suite")
}

// Statement is signed as length-prefixed UTF-8 fields, never as JSON.
// Nonce is standard padded base64. KeyID and DocumentSHA256 are lowercase hex.
type Statement struct {
	Operation      string `json:"operation"`
	Suite          string `json:"suite"`
	ChallengeID    string `json:"challengeId"`
	Nonce          string `json:"nonce"`
	Issuer         string `json:"issuer"`
	Subject        string `json:"subject"`
	KeyID          string `json:"keyId"`
	DocumentSHA256 string `json:"documentSHA256"`
}

func (s Statement) Encode() []byte {
	var out []byte
	for _, f := range []string{"sworn-ink/v1", s.Operation, s.Suite, s.ChallengeID, s.Nonce, s.Issuer, s.Subject, s.KeyID, s.DocumentSHA256} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, []byte(f)...)
	}
	return out
}

// VerifySignature verifies DER ECDSA over SHA-256(statement), exactly once.
func VerifySignature(key *ecdsa.PublicKey, statement, signature []byte) error {
	digest := sha256.Sum256(statement)
	return VerifyDocumentHash(key, digest[:], signature)
}

// VerifyDocumentHash verifies DER ECDSA directly against an already computed
// SHA-256 digest. Do not hash the digest again. Production protocol operations
// use VerifySignature over the complete server-bound statement instead.
func VerifyDocumentHash(key *ecdsa.PublicKey, hash, signature []byte) error {
	if len(hash) != sha256.Size {
		return errors.New("SHA-256 document hash required")
	}
	if key == nil || key.Curve != elliptic.P256() || !key.Curve.IsOnCurve(key.X, key.Y) {
		return errors.New("P-256 key required")
	}
	if !ecdsa.VerifyASN1(key, hash, signature) {
		return errors.New("invalid signature")
	}
	return nil
}
func ValidHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func Hash(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
