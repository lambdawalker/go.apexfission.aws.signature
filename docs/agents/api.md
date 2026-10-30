# Authenticated HTTP API

All three endpoints accept `POST` JSON and require `Authorization: Bearer <access-token>`. Use an operator-provided HTTPS endpoint. Gateway JWT issuer/audience/scopes and Lambda authorizer claims are mandatory. `issuer` and `subject` returned in the challenge are authoritative for the registration statement. There is no email challenge, user creation, token issuance or public evidence-download endpoint.

## POST /v1/challenges

Registration request:

```json
{"operation":"register","suites":["ES256_STRONGBOX","ES256_TEE"]}
```

Signing request (replace placeholders with lowercase 64-character hex digests):

```json
{"operation":"sign","suites":["ES256_STRONGBOX","ES256_TEE"],"keyId":"<leaf-SPKI-SHA256>","documentSHA256":"<document-SHA256>"}
```

Response fields are `challengeId`, `nonce` (base64, 32 decoded bytes), `suite`, `expiresAt` (Unix seconds), `issuer`, `subject`. Signing responses additionally include `statement` (base64 encoded full statement). Registration must omit `keyId` and `documentSHA256`. Signing requires both and a key owned by the authenticated account. At most 16 suite entries are accepted; unknown suites do not enable software cryptography.

## POST /v1/registrations

```json
{"challengeId":"<challengeId>","certificateChain":["<base64-leaf-DER>","<base64-intermediate-DER>"],"signature":"<base64-ASN1-DER-signature>"}
```

Send the attestation chain leaf first. The server validates it against configured roots, derives the SPKI key identifier, reconstructs the registration statement and verifies the signature. The nonce used when generating the key must match the challenge. Success returns `evidenceId`, `keyId`, `timestampStatus`.

## POST /v1/signatures

```json
{"challengeId":"<challengeId>","document":"<base64-original-document>","signature":"<base64-ASN1-DER-signature>"}
```

Decoded document size is at most 512 KiB. The server hashes it independently, loads the account-owned key, revalidates its original attestation including fresh revocation status, reconstructs the statement, then verifies the signature. Success returns `evidenceId`, `keyId`, `timestampStatus`. No timestamp provider is installed by the runtime: `timestampStatus` is `unavailable`.

## HTTP outcomes

All successful routes return `200` JSON after completion. Errors are JSON with an `error` string. Responses use `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

- `400 invalid_json`: malformed, unknown or duplicate JSON fields, wrong typed input or trailing data.
- `400 verification_rejected`: invalid request, document mismatch or rejected attestation/signature.
- `401 unauthorized`: trusted authorizer identity is missing or inconsistent.
- `403 insufficient_scope`: required authorization scope absent.
- `404 not_found`: route, challenge or owned key unavailable.
- `409 expired_or_conflicting_operation`: expired pending challenge, incompatible state or different request bytes.
- `413 request_too_large`: decoded HTTP body exceeds 1 MiB (separate from the document limit).
- `503 unavailable`: service dependency is not configured.
- `503 temporarily_unavailable_retry_same_request`: dependency/storage failure; retain the same decoded request values for recovery.

Reject failures explicitly rather than interpreting missing evidence as success. JSON uses standard base64 binary values and lowercase hex digests; see [Protocol](protocol.md). A transport failure after a write leaves outcome uncertain; [Troubleshooting](troubleshooting.md) explains exact retry semantics. These examples use placeholders, not valid signed test credentials.

## Go embedding API

- `service.Service.CreateChallenge(ctx, Identity, ChallengeRequest)` returns `Challenge`; `Register(ctx, Identity, RegisterRequest)` and `Sign(ctx, Identity, SignRequest)` return `Response`. `Identity.Valid()` bounds issuer/subject and `ID()` derives the storage identity. `Challenge.StatementFor(keyID)` supplies the shared statement.
- Configure `Service.Store`, `Attester`, `Signer` before serving; `TSA` is optional and `Now` is an injectable clock. Required production dependencies must not be nil. Share the configured service across requests only when dependencies are concurrent-safe; it has no `Close` method or owned workers.
- `service.Store` supplies `PutChallenge`, `GetChallenge`, `GetKey`, `Claim`, `Complete`, `GetEvidence`, `PutEvidence`. Custom adapters must preserve conditional state/owner checks, create-only evidence and atomic registration completion. `Complete` takes an optional new key; a nil key completes signing. In-memory test stores are not durable production adapters.
- `service.Attester.Verify` returns a validated `attestation.Result`; `Signer.Sign` receives a 32-byte SHA-256 receipt digest and returns `Seal`. `TimestampProvider` has the stricter trust-validation contract described in [Recipes](recipes.md). `Evidence`, `Envelope`, `Seal`, `Timestamp`, `Key` and `Challenge` define retained JSON shapes in `service/types.go`.
- `attestation.Verifier{Policy: ...}.Verify(ctx, chainDER, nonce, suite)` returns public key, key ID, security level, attestation version and application package. `Policy` requires reviewed `Roots`, `AppPackage`, `AppSignerDigests` and a fail-closed `Revocations` checker; `Now` can inject a clock. `NewGoogleRevocations(*http.Client)` constructs the fixed-endpoint checker; nil uses its default HTTP client policy.
- `awsstore.NewStore(DynamoDBAPI, S3API, table, bucket)` implements durable storage; `NewKMSSigner(KMSAPI, keyID)` implements receipt signing and verifies the resolved key/signature. Clients use AWS SDK v2 method contracts and context cancellation. The evidence bundle bound is 2 MiB, separate from the document/HTTP limits.
- `api.Handler{Service, Issuer, Scope}.Handle(ctx, events.APIGatewayV2HTTPRequest)` returns the Gateway response. Pass only trusted Gateway events; request headers do not substitute for authorizer context. Configure issuer/scope consistently with Gateway.
- `protocol.SelectSuite`, `Statement.Encode`, `VerifySignature`, `VerifyDocumentHash`, `ValidHash` and `Hash` are the wire/cryptographic helpers described in [Protocol](protocol.md). `StrongBox`, `TEE` and `MaxDocumentBytes` expose the policy constants.

Service sentinel errors are `ErrInvalid`, `ErrNotFound` and `ErrConflict`; use `errors.Is`, because errors may be wrapped. Other dependency errors are transient/unavailable at the HTTP boundary. For real working test fixtures see `service/service_test.go`, `attestation/attestation_test.go` and `awsstore/*_test.go`; their synthetic keys and permissive fake attesters are test-only and must not be installed as production trust policy.
