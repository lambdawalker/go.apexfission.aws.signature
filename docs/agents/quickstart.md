# Build and integrate

Development only: there is no confirmed module release, package installation version or public API URL. Clone the coordinated source branch and review the [security policy](security.md) before operating a verifier. The module declares Go 1.26.0; use the matching toolchain. Python 3.11+ builds the docs without third-party packages. Pulumi and deployment prerequisites belong to the operations guide, not the consumer installation path.

```bash
git clone --branch feat/sworn-ink-signatures https://github.com/lambdawalker/go.apexfission.aws.signature.git
cd go.apexfission.aws.signature
go test -race ./...
go vet ./...
GOOS=linux GOARCH=arm64 go build -o build/bootstrap ./cmd/api
python3 sites/build.py --check
```

The commands are local validation/build steps and do not provision AWS. Inspect the workflow results for this revision; documentation does not establish that a particular device or AWS deployment passed. To view human docs after building, run `python3 -m http.server 8000 --directory sites/dist` and open `http://localhost:8000`.

## Integration sequence

- Obtain an access token from your existing trusted issuer. Account identity is the exact JWT issuer and subject. Email verification and token issuance stay with that issuer.
- Discover Android capabilities and request a `register` challenge with supported suites. Use only the server-selected suite. Do not silently fall back when key generation fails.
- Generate an attested Android key with the decoded nonce as its attestation challenge. Compute `keyId` from the leaf SubjectPublicKeyInfo DER and construct the registration statement.
- Ask Android BiometricPrompt to authorize signing that statement; submit the leaf-first certificate chain and DER signature to `/v1/registrations`.
- Hash the exact document bytes. Request a `sign` challenge with `keyId`, digest and supported suite; authorize the returned statement with BiometricPrompt and submit the original document and signature to `/v1/signatures`.
- Treat the operation as complete only when evidence persistence and conditional completion succeed. Retain the returned `evidenceId` and `keyId`.

[HTTP API](api.md) gives request shapes. [Protocol](protocol.md) defines statement bytes. [Android integration](https://github.com/lambdawalker/android.apexfission.signature/blob/feat/sworn-ink-signatures/docs/agents/installation.md) owns client APIs; do not copy backend Go declarations into Kotlin.
