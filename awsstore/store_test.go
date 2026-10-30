package awsstore

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dt "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/lambdawalker/go.apexfission.aws.signature/service"
	"io"
	"strings"
	"testing"
)

type fakeDDB struct {
	put    func(*dynamodb.PutItemInput) error
	get    func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error)
	update func(*dynamodb.UpdateItemInput) error
	tx     func(*dynamodb.TransactWriteItemsInput) error
}

func (f fakeDDB) PutItem(_ context.Context, i *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	return &dynamodb.PutItemOutput{}, f.put(i)
}
func (f fakeDDB) GetItem(_ context.Context, i *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	return f.get(i)
}
func (f fakeDDB) UpdateItem(_ context.Context, i *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	return &dynamodb.UpdateItemOutput{}, f.update(i)
}
func (f fakeDDB) TransactWriteItems(_ context.Context, i *dynamodb.TransactWriteItemsInput, _ ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	return &dynamodb.TransactWriteItemsOutput{}, f.tx(i)
}

type fakeS3 struct {
	get func(*s3.GetObjectInput) (*s3.GetObjectOutput, error)
	put func(*s3.PutObjectInput) error
}

func (f fakeS3) GetObject(_ context.Context, i *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return f.get(i)
}
func (f fakeS3) PutObject(_ context.Context, i *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	return &s3.PutObjectOutput{}, f.put(i)
}
func record(c service.Challenge) map[string]dt.AttributeValue {
	b, _ := json.Marshal(c)
	return map[string]dt.AttributeValue{"pk": sv("challenge#" + c.ID), "data": sv(string(b)), "status": sv(c.Status), "requestHash": sv(c.RequestHash)}
}
func TestChallengeCreateAndClaimConditions(t *testing.T) {
	c := service.Challenge{ID: "abc", Status: "pending", ExpiresAt: 123}
	d := fakeDDB{put: func(i *dynamodb.PutItemInput) error {
		if i.Item["ttlAt"] == nil {
			t.Fatal("missing separate recovery retention TTL")
		}
		if aws.ToString(i.ConditionExpression) != "attribute_not_exists(pk)" || i.Item["expiresAt"].(*dt.AttributeValueMemberN).Value != "123" {
			t.Fatal("unsafe create")
		}
		return nil
	}, update: func(i *dynamodb.UpdateItemInput) error {
		condition := aws.ToString(i.ConditionExpression)
		for _, s := range []string{"#status = :pending", "expiresAt > :now"} {
			if !strings.Contains(condition, s) {
				t.Fatalf("claim lacks %s: %s", s, condition)
			}
		}
		if i.ExpressionAttributeValues[":hash"].(*dt.AttributeValueMemberS).Value != "h" {
			t.Fatal("missing request binding")
		}
		return nil
	}}
	s := NewStore(d, nil, "table", "bucket")
	if err := s.PutChallenge(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if err := s.Claim(context.Background(), "abc", "h", 100); err != nil {
		t.Fatal(err)
	}
}
func TestClaimRetriesBoundToExactHash(t *testing.T) {
	for _, status := range []string{"processing", "complete", "pending"} {
		for _, hash := range []string{"same", "different"} {
			t.Run(status+hash, func(t *testing.T) {
				d := fakeDDB{update: func(*dynamodb.UpdateItemInput) error { return &dt.ConditionalCheckFailedException{} }, get: func(i *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
					if !aws.ToBool(i.ConsistentRead) {
						t.Fatal("retry requires consistent read")
					}
					return &dynamodb.GetItemOutput{Item: record(service.Challenge{ID: "abc", Status: status, RequestHash: hash})}, nil
				}}
				err := NewStore(d, nil, "t", "b").Claim(context.Background(), "abc", "same", 100)
				want := hash == "same" && status != "pending"
				if (err == nil) != want {
					t.Fatalf("got %v", err)
				}
			})
		}
	}
}
func TestKeyNamespaceAndCompleteTransaction(t *testing.T) {
	o := service.Identity{Issuer: "issuer", Subject: "sub"}
	k := service.Key{ID: "key", Owner: o, RegistrationID: "abc"}
	c := service.Challenge{ID: "abc", Owner: o, RequestHash: "hash", Status: "processing"}
	d := fakeDDB{get: func(i *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
		if i.Key["pk"].(*dt.AttributeValueMemberS).Value != "key#"+o.ID()+"#key" {
			t.Fatal("unscoped key")
		}
		return &dynamodb.GetItemOutput{}, nil
	}, tx: func(i *dynamodb.TransactWriteItemsInput) error {
		if len(i.TransactItems) != 2 {
			t.Fatal("registration must be atomic")
		}
		u := i.TransactItems[0].Update
		p := i.TransactItems[1].Put
		if !strings.Contains(aws.ToString(u.ConditionExpression), "requestHash = :hash") || !strings.Contains(aws.ToString(u.ConditionExpression), "#status = :processing") || aws.ToString(p.ConditionExpression) != "attribute_not_exists(pk)" {
			t.Fatal("unsafe transaction")
		}
		return nil
	}}
	s := NewStore(d, nil, "t", "b")
	if _, err := s.GetKey(context.Background(), o, "key"); !errors.Is(err, service.ErrNotFound) {
		t.Fatal(err)
	}
	if err := s.Complete(context.Background(), c, &k); err != nil {
		t.Fatal(err)
	}
}
func TestCompleteExactRetry(t *testing.T) {
	o := service.Identity{Issuer: "i", Subject: "s"}
	k := service.Key{ID: "key", Owner: o, RegistrationID: "abc"}
	c := service.Challenge{ID: "abc", Owner: o, Status: "complete", RequestHash: "hash"}
	for _, mutate := range []bool{false, true} {
		d := fakeDDB{tx: func(*dynamodb.TransactWriteItemsInput) error {
			return &dt.TransactionCanceledException{CancellationReasons: []dt.CancellationReason{{Code: aws.String("ConditionalCheckFailed")}}}
		}, get: func(i *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			pk := i.Key["pk"].(*dt.AttributeValueMemberS).Value
			if strings.HasPrefix(pk, "challenge#") {
				return &dynamodb.GetItemOutput{Item: record(c)}, nil
			}
			stored := k
			if mutate {
				stored.RegistrationID = "different"
			}
			b, _ := json.Marshal(stored)
			return &dynamodb.GetItemOutput{Item: map[string]dt.AttributeValue{"data": sv(string(b))}}, nil
		}}
		err := NewStore(d, nil, "t", "b").Complete(context.Background(), c, &k)
		if (err == nil) == mutate {
			t.Fatalf("mutate=%v err=%v", mutate, err)
		}
	}
}

type closeReader struct {
	io.Reader
	closed bool
}

func (r *closeReader) Close() error { r.closed = true; return nil }
func TestS3ImmutableEvidenceAndReadLimit(t *testing.T) {
	r := &closeReader{Reader: strings.NewReader(strings.Repeat("x", MaxEvidenceBytes+1))}
	f := fakeS3{put: func(i *s3.PutObjectInput) error {
		if aws.ToString(i.IfNoneMatch) != "*" || aws.ToString(i.ContentType) != "application/json" || aws.ToString(i.Key) != "evidence/abc.json" {
			t.Fatal("unsafe evidence write")
		}
		return &smithy.GenericAPIError{Code: "PreconditionFailed"}
	}, get: func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) { return &s3.GetObjectOutput{Body: r}, nil }}
	s := NewStore(nil, f, "t", "b")
	if err := s.PutEvidence(context.Background(), "abc", []byte("{}")); !errors.Is(err, service.ErrConflict) {
		t.Fatal(err)
	}
	if _, err := s.GetEvidence(context.Background(), "abc"); err == nil {
		t.Fatal("oversized evidence accepted")
	}
	if !r.closed {
		t.Fatal("body leaked")
	}
}
func TestS3NotFoundAndServiceError(t *testing.T) {
	for _, code := range []string{"NoSuchKey", "AccessDenied"} {
		s := NewStore(nil, fakeS3{get: func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) { return nil, &smithy.GenericAPIError{Code: code} }}, "t", "b")
		_, err := s.GetEvidence(context.Background(), "abc")
		if errors.Is(err, service.ErrNotFound) != (code == "NoSuchKey") {
			t.Fatalf("%s: %v", code, err)
		}
	}
}

func TestDynamoErrorsAndRecordIntegrity(t *testing.T) {
	ctx := context.Background()
	if err := NewStore(fakeDDB{put: func(*dynamodb.PutItemInput) error { return &dt.ConditionalCheckFailedException{} }}, nil, "t", "b").PutChallenge(ctx, service.Challenge{}); !errors.Is(err, service.ErrConflict) {
		t.Fatal(err)
	}
	denial := errors.New("denied")
	d := fakeDDB{update: func(*dynamodb.UpdateItemInput) error { return denial }}
	if err := NewStore(d, nil, "t", "b").Claim(ctx, "id", "h", 100); !errors.Is(err, denial) {
		t.Fatal(err)
	}
	owner := service.Identity{Issuer: "i", Subject: "s"}
	wrong := service.Key{ID: "key", Owner: service.Identity{Issuer: "i", Subject: "other"}}
	b, _ := json.Marshal(wrong)
	d = fakeDDB{get: func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
		return &dynamodb.GetItemOutput{Item: map[string]dt.AttributeValue{"data": sv(string(b))}}, nil
	}}
	if _, err := NewStore(d, nil, "t", "b").GetKey(ctx, owner, "key"); err == nil {
		t.Fatal("stored key ownership mismatch accepted")
	}
	d = fakeDDB{get: func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
		return &dynamodb.GetItemOutput{Item: record(service.Challenge{ID: "other"})}, nil
	}}
	if _, err := NewStore(d, nil, "t", "b").GetChallenge(ctx, "id"); err == nil {
		t.Fatal("stored challenge ID mismatch accepted")
	}
}
func TestSigningCompletionAndTransactionFailure(t *testing.T) {
	c := service.Challenge{ID: "id", RequestHash: "hash", Status: "complete"}
	stored := record(c)
	d := fakeDDB{update: func(i *dynamodb.UpdateItemInput) error {
		if aws.ToString(i.ConditionExpression) != "#status = :processing AND requestHash = :hash" {
			t.Fatal("unbound signing completion")
		}
		return &dt.ConditionalCheckFailedException{}
	}, get: func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
		return &dynamodb.GetItemOutput{Item: stored}, nil
	}}
	s := NewStore(d, nil, "t", "b")
	if err := s.Complete(context.Background(), c, nil); err != nil {
		t.Fatal(err)
	}
	c.RequestHash = "different"
	if err := s.Complete(context.Background(), c, nil); !errors.Is(err, service.ErrConflict) {
		t.Fatal("different request completed", err)
	}
	failure := &dt.TransactionCanceledException{CancellationReasons: []dt.CancellationReason{{Code: aws.String("ProvisionedThroughputExceeded")}}}
	d = fakeDDB{tx: func(*dynamodb.TransactWriteItemsInput) error { return failure }}
	k := service.Key{RegistrationID: c.ID}
	if err := NewStore(d, nil, "t", "b").Complete(context.Background(), c, &k); !errors.Is(err, failure) {
		t.Fatal("transaction infrastructure error hidden", err)
	}
}
func TestS3WriteAndReadErrors(t *testing.T) {
	denial := errors.New("denied")
	f := fakeS3{put: func(*s3.PutObjectInput) error { return denial }, get: func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader("{}"))}, nil
	}}
	s := NewStore(nil, f, "t", "b")
	if err := s.PutEvidence(context.Background(), "id", []byte("{}")); !errors.Is(err, denial) {
		t.Fatal(err)
	}
	if err := s.PutEvidence(context.Background(), "id", make([]byte, MaxEvidenceBytes+1)); !errors.Is(err, service.ErrInvalid) {
		t.Fatal(err)
	}
	if b, err := s.GetEvidence(context.Background(), "id"); err != nil || string(b) != "{}" {
		t.Fatal(string(b), err)
	}
}

func TestEvidenceFitsMaximumDocumentAndChain(t *testing.T) {
	// Base64 expands the permitted 512KiB document + 256KiB chain above 1MiB.
	// The storage cap must include the statement and receipt envelope too.
	evidence := service.Evidence{Document: make([]byte, 512*1024), Key: service.Key{CertificateChain: [][]byte{make([]byte, 256*1024)}}}
	b, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	f := fakeS3{put: func(*s3.PutObjectInput) error { return nil }}
	if err = NewStore(nil, f, "t", "b").PutEvidence(context.Background(), "id", b); err != nil {
		t.Fatal(err)
	}
}
