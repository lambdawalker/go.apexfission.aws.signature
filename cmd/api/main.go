package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/lambdawalker/go.apexfission.aws.signature/api"
	"github.com/lambdawalker/go.apexfission.aws.signature/attestation"
	"github.com/lambdawalker/go.apexfission.aws.signature/awsstore"
	"github.com/lambdawalker/go.apexfission.aws.signature/service"
	"io"
	"log"
	"os"
	"time"
)

func rootsObject(ctx context.Context, client *s3.Client, c configuration) ([]byte, error) {
	out, e := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(c.rootsBucket), Key: aws.String(c.rootsKey)})
	if e != nil {
		return nil, e
	}
	defer out.Body.Close()
	b, e := io.ReadAll(io.LimitReader(out.Body, 64*1024+1))
	if e != nil {
		return nil, e
	}
	h := sha256.Sum256(b)
	if len(b) > 64*1024 || hex.EncodeToString(h[:]) != c.rootsHash {
		return nil, errors.New("Google root object integrity mismatch")
	}
	return b, nil
}
func buildHandler(ctx context.Context) (api.Handler, error) {
	c, e := readConfig(os.Getenv)
	if e != nil {
		return api.Handler{}, e
	}
	awsConfig, e := config.LoadDefaultConfig(ctx)
	if e != nil {
		return api.Handler{}, e
	}
	s3Client := s3.NewFromConfig(awsConfig)
	roots := []byte(c.rootsPEM)
	if len(roots) == 0 {
		roots, e = rootsObject(ctx, s3Client, c)
		if e != nil {
			return api.Handler{}, e
		}
	}
	pool, e := parseRoots(roots)
	if e != nil {
		return api.Handler{}, e
	}
	svc := &service.Service{Store: awsstore.NewStore(dynamodb.NewFromConfig(awsConfig), s3Client, c.table, c.bucket), Signer: awsstore.NewKMSSigner(kms.NewFromConfig(awsConfig), c.receiptKey), Attester: &attestation.Verifier{Policy: attestation.Policy{Roots: pool, AppPackage: c.app, AppSignerDigests: c.digests, Revocations: attestation.NewGoogleRevocations(nil)}}}
	return api.Handler{Service: svc, Issuer: c.issuer, Scope: c.scope}, nil
}
func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	h, e := buildHandler(ctx)
	cancel()
	if e != nil {
		log.Fatal("signature service configuration failed: ", e)
	}
	lambda.Start(h.Handle)
}
