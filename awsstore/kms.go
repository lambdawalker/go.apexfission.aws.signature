package awsstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kt "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/lambdawalker/go.apexfission.aws.signature/service"
)

// KMSAPI is implemented by the AWS SDK v2 KMS client.
type KMSAPI interface {
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}

// KMSSigner signs SHA-256 digests using a P-256 asymmetric KMS key.
type KMSSigner struct {
	client KMSAPI
	keyID  string
}

var _ service.Signer = (*KMSSigner)(nil)

func NewKMSSigner(client KMSAPI, keyID string) *KMSSigner {
	return &KMSSigner{client: client, keyID: keyID}
}
func (s *KMSSigner) Sign(ctx context.Context, digest []byte) (service.Seal, error) {
	var seal service.Seal
	if len(digest) != sha256.Size {
		return seal, fmt.Errorf("%w: KMS requires a SHA-256 digest", service.ErrInvalid)
	}
	pub, err := s.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(s.keyID)})
	if err != nil {
		return seal, fmt.Errorf("get KMS public key: %w", err)
	}
	if pub == nil || aws.ToString(pub.KeyId) == "" || pub.KeyUsage != kt.KeyUsageTypeSignVerify || pub.KeySpec != kt.KeySpecEccNistP256 {
		return seal, errors.New("KMS key must be a P-256 signing key")
	}
	supported := false
	for _, alg := range pub.SigningAlgorithms {
		if alg == kt.SigningAlgorithmSpecEcdsaSha256 {
			supported = true
		}
	}
	if !supported {
		return seal, errors.New("KMS key does not support ECDSA_SHA_256")
	}
	parsed, err := x509.ParsePKIXPublicKey(pub.PublicKey)
	if err != nil {
		return seal, fmt.Errorf("parse KMS public key: %w", err)
	}
	ec, ok := parsed.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return seal, errors.New("KMS public key is not P-256")
	}
	// Resolve aliases before signing and use the returned immutable key identity.
	signed, err := s.client.Sign(ctx, &kms.SignInput{KeyId: pub.KeyId, Message: append([]byte(nil), digest...), MessageType: kt.MessageTypeDigest, SigningAlgorithm: kt.SigningAlgorithmSpecEcdsaSha256})
	if err != nil {
		return seal, fmt.Errorf("KMS sign: %w", err)
	}
	if signed == nil || aws.ToString(signed.KeyId) != aws.ToString(pub.KeyId) || signed.SigningAlgorithm != kt.SigningAlgorithmSpecEcdsaSha256 || !ecdsa.VerifyASN1(ec, digest, signed.Signature) {
		return seal, errors.New("KMS returned an inconsistent signature")
	}
	return service.Seal{Algorithm: string(kt.SigningAlgorithmSpecEcdsaSha256), KeyID: aws.ToString(pub.KeyId), PublicKeyDER: append([]byte(nil), pub.PublicKey...), Signature: append([]byte(nil), signed.Signature...)}, nil
}
