package infrastructure

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"
	"net/url"
	"os"
	"regexp"
	"strings"
)

type settings struct{ Issuer, Audience, Scope, Package, Digests, Roots string }

func (c settings) validate() error {
	u, e := url.Parse(c.Issuer)
	if e != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("HTTPS jwtIssuer required")
	}
	if c.Audience == "" || c.Scope == "" || c.Package == "" {
		return errors.New("audience, scope and appPackage required")
	}
	return c.validateTrust()
}

func (c settings) validateTrust() error {
	if c.Package == "" {
		return errors.New("appPackage required")
	}
	for _, d := range strings.Split(c.Digests, ",") {
		b, e := hex.DecodeString(d)
		if e != nil || len(b) != 32 {
			return errors.New("appDigests must be comma separated SHA256 hex")
		}
	}
	rest := []byte(c.Roots)
	n := 0
	for len(strings.TrimSpace(string(rest))) > 0 {
		b, r := pem.Decode(rest)
		if b == nil || b.Type != "CERTIFICATE" {
			return errors.New("reviewed PEM roots required")
		}
		cert, e := x509.ParseCertificate(b.Bytes)
		if e != nil || !cert.IsCA || cert.CheckSignatureFrom(cert) != nil {
			return errors.New("root must be a self-signed CA")
		}
		n++
		rest = r
	}
	if n == 0 {
		return errors.New("roots required")
	}
	return nil
}
func js(v any) string { b, _ := json.Marshal(v); return string(b) }
func lambdaPolicy(table, bucket, storage, receipt string) string {
	return js(map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Action": []string{"dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:UpdateItem"}, "Resource": table}, map[string]any{"Effect": "Allow", "Action": []string{"s3:GetObject", "s3:PutObject"}, "Resource": bucket + "/evidence/*"}, map[string]any{"Effect": "Allow", "Action": []string{"s3:GetObject"}, "Resource": bucket + "/config/google-roots.pem"}, map[string]any{"Effect": "Allow", "Action": []string{"kms:GenerateDataKey", "kms:Decrypt"}, "Resource": storage}, map[string]any{"Effect": "Allow", "Action": []string{"kms:Sign", "kms:GetPublicKey"}, "Resource": receipt}}})
}

type resource struct {
	pulumi.CustomResourceState
	Arn          pulumi.StringOutput `pulumi:"arn"`
	Name         pulumi.StringOutput `pulumi:"name"`
	InvokeArn    pulumi.StringOutput `pulumi:"invokeArn"`
	Endpoint     pulumi.StringOutput `pulumi:"apiEndpoint"`
	ExecutionArn pulumi.StringOutput `pulumi:"executionArn"`
}

// Options configures feature-owned resources. Prefix isolates logical names in a host stack.
type Options struct {
	BoundaryARN             string
	Prefix                  string
	Artifact                string
	Issuer, Audience, Scope pulumi.StringInput
	ResourceOptions         []pulumi.ResourceOption
}
type Deployment struct {
	Resource                               pulumi.Resource
	APIURL, Bucket, StateTable, ReceiptKey pulumi.StringOutput
}

func Deploy(ctx *pulumi.Context, cfg *config.Config, opts Options) (*Deployment, error) {
	c := settings{Package: cfg.Require("appPackage"), Digests: cfg.Require("appDigests"), Roots: cfg.Require("googleRootsPEM")}
	if e := c.validateTrust(); e != nil {
		return nil, e
	}
	if opts.Issuer == nil || opts.Audience == nil || opts.Scope == nil {
		return nil, errors.New("JWT identity inputs required")
	}
	issuer := opts.Issuer.ToStringOutput().ApplyT(func(v string) (string, error) {
		u, e := url.Parse(v)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return "", errors.New("HTTPS JWT issuer required")
		}
		return v, nil
	}).(pulumi.StringOutput)
	nonempty := func(input pulumi.StringInput) pulumi.StringOutput {
		return input.ToStringOutput().ApplyT(func(v string) (string, error) {
			if strings.TrimSpace(v) == "" {
				return "", errors.New("JWT audience/scope required")
			}
			return v, nil
		}).(pulumi.StringOutput)
	}
	audience, scope := nonempty(opts.Audience), nonempty(opts.Scope)
	artifact := opts.Artifact
	if artifact == "" {
		artifact = cfg.Get("artifact")
	}
	if artifact == "" {
		artifact = "../build/bootstrap.zip"
	}
	b, e := os.ReadFile(artifact)
	if e != nil {
		return nil, fmt.Errorf("build artifact first: %w", e)
	}
	hash := sha256.Sum256(b)
	var failed error
	add := func(token, name string, args pulumi.Map, resourceOpts ...pulumi.ResourceOption) *resource {
		r := &resource{}
		if failed == nil {
			failed = ctx.RegisterResource("aws:"+token, opts.Prefix+name, args, r, append(append(resourceOpts, opts.ResourceOptions...), pulumi.Version("7.44.0"))...)
		}
		return r
	}
	s := func(v string) pulumi.String { return pulumi.String(v) }
	identity := ctx.Project() + "-" + ctx.Stack()
	if opts.Prefix != "" {
		identity += "-" + strings.TrimSuffix(opts.Prefix, "-")
	}
	account := cfg.Require("awsAccount")
	region := config.Require(ctx, "aws:region")
	if e := validateResourceIdentity(ctx.Stack(), account, region); e != nil {
		return nil, e
	}
	boundary := opts.BoundaryARN
	if boundary == "" {
		boundary = "arn:aws:iam::" + account + ":policy/" + identity + "-runtime-boundary"
	}
	tags := pulumi.StringMap{"Project": s("sworn-ink"), "Environment": s(ctx.Stack())}
	yes := pulumi.Bool(true)
	storage := add("kms/key:Key", "storage", pulumi.Map{"tags": tags, "enableKeyRotation": yes, "deletionWindowInDays": pulumi.Int(30)})
	receipt := add("kms/key:Key", "receipt", pulumi.Map{"tags": tags, "customerMasterKeySpec": s("ECC_NIST_P256"), "keyUsage": s("SIGN_VERIFY"), "deletionWindowInDays": pulumi.Int(30)})
	bucket := add("s3/bucket:Bucket", "evidence", pulumi.Map{"bucket": s("sworn-ink-" + account + "-" + region + "-" + ctx.Stack() + "-evidence"), "tags": tags, "forceDestroy": pulumi.Bool(false), "versioning": pulumi.Map{"enabled": yes}, "serverSideEncryptionConfiguration": pulumi.Map{"rule": pulumi.Map{"applyServerSideEncryptionByDefault": pulumi.Map{"sseAlgorithm": s("aws:kms"), "kmsMasterKeyId": storage.Arn}}}})
	add("s3/bucketPublicAccessBlock:BucketPublicAccessBlock", "private", pulumi.Map{"bucket": bucket.ID(), "blockPublicAcls": yes, "blockPublicPolicy": yes, "ignorePublicAcls": yes, "restrictPublicBuckets": yes})
	add("s3/bucketPolicy:BucketPolicy", "tls", pulumi.Map{"bucket": bucket.ID(), "policy": bucket.Arn.ApplyT(func(a string) string {
		return js(map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": []string{a, a + "/*"}, "Condition": map[string]any{"Bool": map[string]string{"aws:SecureTransport": "false"}}}}})
	})})
	table := add("dynamodb/table:Table", "state", pulumi.Map{"name": s(identity + "-state"), "tags": tags, "billingMode": s("PAY_PER_REQUEST"), "hashKey": s("pk"), "attributes": pulumi.Array{pulumi.Map{"name": s("pk"), "type": s("S")}}, "ttl": pulumi.Map{"attributeName": s("ttlAt"), "enabled": yes}, "pointInTimeRecovery": pulumi.Map{"enabled": yes}, "serverSideEncryption": pulumi.Map{"enabled": yes, "kmsKeyArn": storage.Arn}})
	role := add("iam/role:Role", "lambda", pulumi.Map{"name": s(identity + "-lambda"), "tags": tags, "permissionsBoundary": s(boundary), "assumeRolePolicy": s(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)})
	policy := add("iam/rolePolicy:RolePolicy", "data", pulumi.Map{"role": role.ID(), "policy": pulumi.All(table.Arn, bucket.Arn, storage.Arn, receipt.Arn).ApplyT(func(v []any) string { return lambdaPolicy(v[0].(string), v[1].(string), v[2].(string), v[3].(string)) })})
	rootsHash := sha256.Sum256([]byte(c.Roots))
	roots := add("s3/bucketObject:BucketObject", "google-roots", pulumi.Map{"bucket": bucket.ID(), "key": s("config/google-roots.pem"), "content": s(c.Roots), "serverSideEncryption": s("aws:kms"), "kmsKeyId": storage.Arn})
	name := identity
	retention := cfg.GetInt("logRetentionDays")
	if retention == 0 {
		retention = 30
	}
	logs := add("cloudwatch/logGroup:LogGroup", "logs", pulumi.Map{"name": s("/aws/lambda/" + name), "retentionInDays": pulumi.Int(retention)})
	logPolicy := add("iam/rolePolicy:RolePolicy", "logs", pulumi.Map{"role": role.ID(), "policy": logs.Arn.ApplyT(func(a string) string {
		return js(map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Action": []string{"logs:CreateLogStream", "logs:PutLogEvents"}, "Resource": strings.TrimSuffix(a, ":*") + ":*"}}})
	})})
	fn := add("lambda/function:Function", "api", pulumi.Map{"name": s(name), "role": role.Arn, "runtime": s("provided.al2023"), "architectures": pulumi.StringArray{s("arm64")}, "handler": s("bootstrap"), "code": pulumi.NewFileArchive(artifact), "sourceCodeHash": s(base64.StdEncoding.EncodeToString(hash[:])), "timeout": pulumi.Int(30), "memorySize": pulumi.Int(256), "environment": pulumi.Map{"variables": pulumi.Map{"DOCUMENT_BUCKET": bucket.ID(), "STATE_TABLE": table.Name, "RECEIPT_KEY_ID": receipt.Arn, "GOOGLE_ROOTS_BUCKET": bucket.ID(), "GOOGLE_ROOTS_KEY": s("config/google-roots.pem"), "GOOGLE_ROOTS_SHA256": s(hex.EncodeToString(rootsHash[:])), "JWT_SCOPE": scope, "ALLOWED_APP_PACKAGE": s(c.Package), "ALLOWED_APP_DIGESTS": s(c.Digests), "JWT_ISSUER": issuer}}}, pulumi.DependsOn([]pulumi.Resource{policy, logPolicy, logs, roots}))
	api := add("apigatewayv2/api:Api", "http", pulumi.Map{"tags": tags, "protocolType": s("HTTP")})
	auth := add("apigatewayv2/authorizer:Authorizer", "jwt", pulumi.Map{"apiId": api.ID(), "authorizerType": s("JWT"), "identitySources": pulumi.StringArray{s("$request.header.Authorization")}, "jwtConfiguration": pulumi.Map{"issuer": issuer, "audiences": pulumi.StringArray{audience}}})
	integration := add("apigatewayv2/integration:Integration", "lambda", pulumi.Map{"apiId": api.ID(), "integrationType": s("AWS_PROXY"), "integrationUri": fn.InvokeArn, "payloadFormatVersion": s("2.0")})
	for _, r := range []string{"challenges", "registrations", "signatures"} {
		add("apigatewayv2/route:Route", r, pulumi.Map{"apiId": api.ID(), "routeKey": s("POST /v1/" + r), "target": pulumi.Sprintf("integrations/%s", integration.ID()), "authorizationType": s("JWT"), "authorizerId": auth.ID(), "authorizationScopes": pulumi.StringArray{scope}})
	}
	stage := add("apigatewayv2/stage:Stage", "default", pulumi.Map{"apiId": api.ID(), "name": s("$default"), "autoDeploy": yes, "defaultRouteSettings": pulumi.Map{"throttlingBurstLimit": pulumi.Int(20), "throttlingRateLimit": pulumi.Float64(10)}})
	add("lambda/permission:Permission", "gateway", pulumi.Map{"action": s("lambda:InvokeFunction"), "function": fn.Name, "principal": s("apigateway.amazonaws.com"), "sourceArn": pulumi.Sprintf("%s/*/*", api.ExecutionArn)})
	if failed != nil {
		return nil, failed
	}
	return &Deployment{Resource: stage, APIURL: api.Endpoint, Bucket: bucket.ID().ToStringOutput(), StateTable: table.Name, ReceiptKey: receipt.Arn}, nil
}

// Keep names within S3's 63-byte limit, including longer commercial AWS regions.
func validateResourceIdentity(stack, account, region string) error {
	if !regexp.MustCompile(`^[a-z][a-z0-9-]{0,15}$`).MatchString(stack) || !regexp.MustCompile(`^[0-9]{12}$`).MatchString(account) || len("sworn-ink-"+account+"-"+region+"-"+stack+"-evidence") > 63 {
		return errors.New("invalid AWS resource identity: environment must contain 1..16 lowercase characters and account must be 12 digits")
	}
	return nil
}
