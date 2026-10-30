package awsstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kt "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"testing"
)

type fakeKMS struct {
	get  func(*kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error)
	sign func(*kms.SignInput) (*kms.SignOutput, error)
}

func (f fakeKMS) GetPublicKey(_ context.Context, i *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return f.get(i)
}
func (f fakeKMS) Sign(_ context.Context, i *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	return f.sign(i)
}
func TestKMSSignsDigestAndPinsResolvedKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	d := sha256.Sum256([]byte("evidence"))
	called := false
	f := fakeKMS{get: func(*kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
		return &kms.GetPublicKeyOutput{KeyId: aws.String("arn:resolved"), PublicKey: der, KeyUsage: kt.KeyUsageTypeSignVerify, KeySpec: kt.KeySpecEccNistP256, SigningAlgorithms: []kt.SigningAlgorithmSpec{kt.SigningAlgorithmSpecEcdsaSha256}}, nil
	}, sign: func(i *kms.SignInput) (*kms.SignOutput, error) {
		called = true
		if aws.ToString(i.KeyId) != "arn:resolved" || i.MessageType != kt.MessageTypeDigest || i.SigningAlgorithm != kt.SigningAlgorithmSpecEcdsaSha256 || string(i.Message) != string(d[:]) {
			t.Fatal("incorrect signing request")
		}
		sig, _ := ecdsa.SignASN1(rand.Reader, key, i.Message)
		return &kms.SignOutput{KeyId: aws.String("arn:resolved"), SigningAlgorithm: kt.SigningAlgorithmSpecEcdsaSha256, Signature: sig}, nil
	}}
	s := NewKMSSigner(f, "alias/receipt")
	if _, err := s.Sign(context.Background(), []byte("too short")); err == nil || called {
		t.Fatal("invalid digest accepted")
	}
	seal, err := s.Sign(context.Background(), d[:])
	if err != nil {
		t.Fatal(err)
	}
	if seal.Algorithm != "ECDSA_SHA_256" || !ecdsa.VerifyASN1(&key.PublicKey, d[:], seal.Signature) || string(seal.PublicKeyDER) != string(der) {
		t.Fatal("invalid seal")
	}
}

func TestKMSRejectsInconsistentSignature(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	digest := sha256.Sum256([]byte("evidence"))
	sig, _ := ecdsa.SignASN1(rand.Reader, key, digest[:])
	for _, scenario := range []string{"different-key", "different-algorithm", "bad-signature", "wrong-key-spec", "wrong-key-usage", "unsupported"} {
		t.Run(scenario, func(t *testing.T) {
			f := fakeKMS{get: func(*kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
				out := &kms.GetPublicKeyOutput{KeyId: aws.String("arn:key"), PublicKey: der, KeyUsage: kt.KeyUsageTypeSignVerify, KeySpec: kt.KeySpecEccNistP256, SigningAlgorithms: []kt.SigningAlgorithmSpec{kt.SigningAlgorithmSpecEcdsaSha256}}
				switch scenario {
				case "wrong-key-spec":
					out.KeySpec = kt.KeySpecRsa2048
				case "wrong-key-usage":
					out.KeyUsage = kt.KeyUsageTypeEncryptDecrypt
				case "unsupported":
					out.SigningAlgorithms = nil
				}
				return out, nil
			}, sign: func(*kms.SignInput) (*kms.SignOutput, error) {
				out := &kms.SignOutput{KeyId: aws.String("arn:key"), SigningAlgorithm: kt.SigningAlgorithmSpecEcdsaSha256, Signature: sig}
				switch scenario {
				case "different-key":
					out.KeyId = aws.String("arn:other")
				case "different-algorithm":
					out.SigningAlgorithm = kt.SigningAlgorithmSpecEcdsaSha384
				case "bad-signature":
					out.Signature = []byte("invalid")
				}
				return out, nil
			}}
			if _, err := NewKMSSigner(f, "arn:key").Sign(context.Background(), digest[:]); err == nil {
				t.Fatal("inconsistent KMS response accepted")
			}
		})
	}
}
