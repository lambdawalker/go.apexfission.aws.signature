# Integration recipes

## Reproduce the shared vector

Use the nine fields in `protocol/test-vectors/v1.json`. Encode their UTF-8 byte lengths and compare every encoded byte with `encodedHex`. This fixture deliberately includes non-ASCII text, an empty digest and base64 text to catch code-point length mistakes. Run the Go protocol tests and Android host encoding tests against the same fixture. Never submit its placeholder challenge as a live request.

```bash
go test ./protocol ./attestation ./service ./api
```

## Register then sign

Follow [Quickstart](quickstart.md), using the [HTTP bodies](api.md). Generate a new key only after receiving the registration nonce. Capture the resulting certificate chain and derive the key identifier from the leaf SPKI. Obtain fresh biometric authorization for each full statement. Hash the exact document bytes that will be submitted, not a rendered preview or a normalized string. Preserve the statement, signature and request if a network timeout requires recovery. Do not store access tokens in logs.

## Verify retained evidence independently

Read the evidence bundle through an authorized operator-controlled storage path; no consumer retrieval API is implemented. Keep the raw payload bytes because the KMS signature covers their SHA-256, not a reserialized interpretation. Verify the DER ECDSA seal using the trusted receipt public key and algorithm. Establish the expected key through trusted operator distribution; an embedded public key alone does not establish trust. Reconstruct statement fields, check original document digest and client signature, owner and challenge, then apply the recorded policy and trusted root/revocation evidence applicable to the verification decision.

`verifiedAt` is a server clock value, not proof of independent time. With an injected timestamp provider, validate its token and imprint binding of payload plus seal under a separately trusted TSA policy. The default runtime has no such provider. Independent validation tooling and a public evidence-download API remain integration work; the current service does not expose a turnkey offline verifier.

## Extend timestamping

Implement `service.TimestampProvider.Timestamp(context.Context, []byte) ([]byte, error)`. Its input is a SHA-256 imprint over the JSON combination of payload and seal. The provider MUST validate TSA trust, imprint, policy, nonce and time before returning a token; returning arbitrary bytes violates the contract. A configured provider failure or empty token aborts completion. No fake TSA, default HTTP RFC3161 client or claimed independent timestamp is supplied.

## Review deployment plans without applying

Use the [deployment tooling guide](https://github.com/lambdawalker/go.apexfission.aws.signature/blob/feat/sworn-ink-signatures/docs/deployment.md) to supply a selected environment, SSO profile, account, region and existing private S3 state prefix. `--action oidc-plan` emits reviewable OIDC trust, deployment IAM policy and runtime boundary without creating them; `--action preview` restores authoritative encrypted stack settings, validates the single-account provider target, builds and saves a refreshed Pulumi plan without applying it. Preview still requires access to the correct encrypted configuration and state. IAM bootstrap is a separate explicitly approved step; a successful plan does not claim live deployment or authorize application.
