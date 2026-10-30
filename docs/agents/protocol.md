# Protocol v1 — authoritative contract

The Go repository owns this contract. Android and Go must produce identical bytes. Wire binary fields use standard padded base64, never base64url. Digests and key identifiers use 64 lowercase SHA-256 hexadecimal characters. Certificate chains contain DER certificates in leaf-first order. ECDSA signatures use ASN.1 DER, never JOSE `r || s`.

## Exact signed statement

Concatenate these nine UTF-8 fields in this exact order. Prefix EACH field with its byte length as an unsigned 32-bit big-endian integer. Empty strings still have a four-byte zero prefix. Length counts UTF-8 bytes, not code points. No separators, trailing newline, Unicode normalization or JSON serialization are added.

- `sworn-ink/v1`
- operation: `register` or `sign`
- selected suite: `ES256_STRONGBOX` or `ES256_TEE`
- `challengeId`
- nonce as its standard padded base64 TEXT, not decoded bytes
- trusted JWT issuer
- trusted JWT subject
- `keyId`: SHA-256 of the leaf certificate SubjectPublicKeyInfo DER
- `documentSHA256`: empty for registration; digest of exact document bytes for signing

`protocol.Statement.Encode()` implements this encoding. For example, the first field is twelve bytes, so the statement begins with hexadecimal `0000000c73776f726e2d696e6b2f7631`. `protocol/protocol_test.go` holds the cross-language encoding vector. The Android encoder must match it; the protocol is independent of JSON member order.

Sign the full encoded statement using Android `SHA256withECDSA`. The verifier hashes the statement once and verifies its DER signature with P-256. Do not prehash the statement before passing it to `SHA256withECDSA`. The Go `VerifyDocumentHash` low-level verifier accepts an already computed 32-byte SHA-256 digest directly, with no extra hashing. Production `VerifySignature` hashes the full encoded statement once and delegates to that verifier. There is no raw-document-hash HTTP signing operation.

## Registration

Request a registration challenge before key generation. Decode its nonce and pass those exact bytes as the Android attestation challenge. Determine `keyId` locally from the resulting leaf SPKI, then encode the registration statement using the same trusted issuer/subject as the access token. The server reconstructs this statement; the registration request does not supply one. The statement returned for signing challenges is base64 of encoded bytes, ready to decode and authorize.

## Agreement and lifetime

A nonce has 32 cryptographically random bytes. Challenges expire after 300 seconds. Registration selects server-preferred supported hardware. Signing preserves the registered hardware suite. Failed hardware selection must not lead to silent fallback. A document is at most 524288 decoded bytes. TLS protects transport, SSE-KMS protects stored evidence, and no application encryption suite is negotiated here.

[HTTP API](api.md) defines messages. [Security](security.md) defines trust. [Android protocol implementation](https://github.com/lambdawalker/android.apexfission.signature/tree/feat/sworn-ink-signatures) must follow this contract.
