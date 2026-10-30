// Package awsstore provides DynamoDB, S3 and KMS adapters for the signature service.
package awsstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dt "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/lambdawalker/go.apexfission.aws.signature/service"
)

// MaxEvidenceBytes bounds both stored evidence and reads, including JSON encoding.
const MaxEvidenceBytes = 2 << 20

// DynamoDBAPI is implemented by the AWS SDK v2 DynamoDB client.
type DynamoDBAPI interface {
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
}

// S3API is implemented by the AWS SDK v2 S3 client.
type S3API interface {
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// Store uses a table with string partition key pk and an SSE-KMS encrypted bucket.
// The bucket's default encryption and IAM policy must enforce the encryption key.
type Store struct {
	dynamo        DynamoDBAPI
	s3            S3API
	table, bucket string
}

var _ service.Store = (*Store)(nil)

func NewStore(dynamo DynamoDBAPI, s3client S3API, table, bucket string) *Store {
	return &Store{dynamo: dynamo, s3: s3client, table: table, bucket: bucket}
}
func sv(s string) dt.AttributeValue            { return &dt.AttributeValueMemberS{Value: s} }
func pk(s string) map[string]dt.AttributeValue { return map[string]dt.AttributeValue{"pk": sv(s)} }
func textAttribute(item map[string]dt.AttributeValue, name string) (string, error) {
	v, ok := item[name].(*dt.AttributeValueMemberS)
	if !ok {
		return "", fmt.Errorf("invalid DynamoDB record: %s must be a string", name)
	}
	return v.Value, nil
}
func conditional(err error) bool {
	var e *dt.ConditionalCheckFailedException
	return errors.As(err, &e)
}
func transactionConditional(err error) bool {
	var e *dt.TransactionCanceledException
	if !errors.As(err, &e) {
		return false
	}
	found := false
	for _, r := range e.CancellationReasons {
		code := aws.ToString(r.Code)
		if code == "ConditionalCheckFailed" {
			found = true
		} else if code != "" && code != "None" {
			return false
		}
	}
	return found
}
func (s *Store) get(ctx context.Context, key string) (map[string]dt.AttributeValue, error) {
	out, err := s.dynamo.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(s.table), Key: pk(key), ConsistentRead: aws.Bool(true)})
	if err != nil {
		return nil, fmt.Errorf("get DynamoDB record: %w", err)
	}
	if out == nil || len(out.Item) == 0 {
		return nil, service.ErrNotFound
	}
	return out.Item, nil
}
func (s *Store) PutChallenge(ctx context.Context, c service.Challenge) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	item := pk("challenge#" + c.ID)
	item["data"] = sv(string(data))
	item["status"] = sv(c.Status)
	item["requestHash"] = sv(c.RequestHash)
	item["expiresAt"] = &dt.AttributeValueMemberN{Value: strconv.FormatInt(c.ExpiresAt, 10)}
	// Authorization expiry is independent of cleanup: preserve exact-retry state for seven days.
	item["ttlAt"] = &dt.AttributeValueMemberN{Value: strconv.FormatInt(c.ExpiresAt+7*24*60*60, 10)}
	_, err = s.dynamo.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(s.table), Item: item, ConditionExpression: aws.String("attribute_not_exists(pk)")})
	if conditional(err) {
		return service.ErrConflict
	}
	if err != nil {
		return fmt.Errorf("put challenge: %w", err)
	}
	return nil
}
func (s *Store) GetChallenge(ctx context.Context, id string) (service.Challenge, error) {
	var c service.Challenge
	item, err := s.get(ctx, "challenge#"+id)
	if err != nil {
		return c, err
	}
	data, err := textAttribute(item, "data")
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal([]byte(data), &c); err != nil {
		return c, fmt.Errorf("decode challenge: %w", err)
	}
	if c.ID != id {
		return c, errors.New("DynamoDB challenge identity mismatch")
	}
	c.Status, err = textAttribute(item, "status")
	if err != nil {
		return c, err
	}
	c.RequestHash, err = textAttribute(item, "requestHash")
	return c, err
}
func (s *Store) GetKey(ctx context.Context, o service.Identity, id string) (service.Key, error) {
	var k service.Key
	item, err := s.get(ctx, "key#"+o.ID()+"#"+id)
	if err != nil {
		return k, err
	}
	data, err := textAttribute(item, "data")
	if err != nil {
		return k, err
	}
	if err = json.Unmarshal([]byte(data), &k); err != nil {
		return k, fmt.Errorf("decode key: %w", err)
	}
	if k.ID != id || k.Owner != o {
		return k, errors.New("DynamoDB key identity mismatch")
	}
	return k, nil
}
func (s *Store) Claim(ctx context.Context, id, hash string, now int64) error {
	_, err := s.dynamo.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: aws.String(s.table), Key: pk("challenge#" + id), UpdateExpression: aws.String("SET #status = :processing, requestHash = :hash"), ConditionExpression: aws.String("#status = :pending AND expiresAt > :now"), ExpressionAttributeNames: map[string]string{"#status": "status"}, ExpressionAttributeValues: map[string]dt.AttributeValue{":pending": sv("pending"), ":processing": sv("processing"), ":hash": sv(hash), ":now": &dt.AttributeValueMemberN{Value: strconv.FormatInt(now, 10)}}})
	if err == nil {
		return nil
	}
	if !conditional(err) {
		return fmt.Errorf("claim challenge: %w", err)
	}
	c, err := s.GetChallenge(ctx, id)
	if err != nil {
		return err
	}
	if c.RequestHash == hash && (c.Status == "processing" || c.Status == "complete") {
		return nil
	}
	return service.ErrConflict
}
func (s *Store) Complete(ctx context.Context, c service.Challenge, k *service.Key) error {
	if k != nil && (k.Owner != c.Owner || k.RegistrationID != c.ID) {
		return service.ErrConflict
	}
	u := &dt.Update{TableName: aws.String(s.table), Key: pk("challenge#" + c.ID), UpdateExpression: aws.String("SET #status = :complete"), ConditionExpression: aws.String("#status = :processing AND requestHash = :hash"), ExpressionAttributeNames: map[string]string{"#status": "status"}, ExpressionAttributeValues: map[string]dt.AttributeValue{":processing": sv("processing"), ":complete": sv("complete"), ":hash": sv(c.RequestHash)}}
	var err error
	if k == nil {
		_, err = s.dynamo.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: u.TableName, Key: u.Key, UpdateExpression: u.UpdateExpression, ConditionExpression: u.ConditionExpression, ExpressionAttributeNames: u.ExpressionAttributeNames, ExpressionAttributeValues: u.ExpressionAttributeValues})
	} else {
		data, e := json.Marshal(k)
		if e != nil {
			return e
		}
		item := pk("key#" + k.Owner.ID() + "#" + k.ID)
		item["data"] = sv(string(data))
		_, err = s.dynamo.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []dt.TransactWriteItem{{Update: u}, {Put: &dt.Put{TableName: aws.String(s.table), Item: item, ConditionExpression: aws.String("attribute_not_exists(pk)")}}}})
	}
	if err == nil {
		return nil
	}
	if !conditional(err) && !transactionConditional(err) {
		return fmt.Errorf("complete challenge: %w", err)
	}
	stored, err := s.GetChallenge(ctx, c.ID)
	if err != nil {
		return err
	}
	if stored.Status != "complete" || stored.RequestHash != c.RequestHash || stored.Owner != c.Owner {
		return service.ErrConflict
	}
	if k != nil {
		existing, e := s.GetKey(ctx, k.Owner, k.ID)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(existing, *k) {
			return service.ErrConflict
		}
	}
	return nil
}
func apiCode(err error) string {
	var e smithy.APIError
	if errors.As(err, &e) {
		return e.ErrorCode()
	}
	return ""
}
func (s *Store) GetEvidence(ctx context.Context, id string) ([]byte, error) {
	out, err := s.s3.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String("evidence/" + id + ".json")})
	if err != nil {
		if apiCode(err) == "NoSuchKey" || apiCode(err) == "NotFound" {
			return nil, service.ErrNotFound
		}
		return nil, fmt.Errorf("get evidence: %w", err)
	}
	if out == nil || out.Body == nil {
		return nil, errors.New("empty S3 response body")
	}
	defer out.Body.Close()
	b, err := io.ReadAll(io.LimitReader(out.Body, MaxEvidenceBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read evidence: %w", err)
	}
	if len(b) > MaxEvidenceBytes {
		return nil, errors.New("evidence exceeds size limit")
	}
	return b, nil
}
func (s *Store) PutEvidence(ctx context.Context, id string, data []byte) error {
	if len(data) > MaxEvidenceBytes {
		return fmt.Errorf("%w: evidence exceeds size limit", service.ErrInvalid)
	}
	_, err := s.s3.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(s.bucket), Key: aws.String("evidence/" + id + ".json"), Body: bytes.NewReader(data), ContentType: aws.String("application/json"), IfNoneMatch: aws.String("*")})
	if err != nil {
		if apiCode(err) == "PreconditionFailed" || apiCode(err) == "ConditionalRequestConflict" {
			return service.ErrConflict
		}
		return fmt.Errorf("put evidence: %w", err)
	}
	return nil
}
