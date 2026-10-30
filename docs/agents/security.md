# Security policy and limits

## Trust inputs

Only operator-reviewed Google hardware attestation roots establish certificate trust. The request's root and the operating system web PKI cannot extend trust. Configure root rotation deliberately, using reviewed source material. Application package AND signing-certificate SHA-256 digest must be allowlisted. JWT issuer, audience and scope are operator settings; runtime requests do not choose trust anchors or identity providers.

## Attestation checks

The verifier checks a full X.509 path and validity/constraints, a P-256 public key, nonce binding, hardware attestation and keymaster security levels, generated origin, signing purpose, EC algorithm/curve/SHA-256 digest, biometric-only per-operation authorization, locked verified boot and the app allowlist. It rejects malformed or duplicate security tags and malformed/untrusted application identity. `noAuthRequired` and timed authorization are rejected. Every verified chain serial is checked against Google's fresh attestation revocation status; stale data or fetch failure fails closed. Signing revalidates the registered chain instead of relying forever on registration-time status.

Android enrollment invalidation is requested locally; the certificate does not explicitly prove that flag. Real enforcement requires Android hardware tests. Capability reporting cannot replace attestation. StrongBox availability and biometric UX differ across devices and API levels; consult the Android companion rather than assuming emulator evidence proves hardware protection.

## Replay and durable evidence

Challenges bind owner, operation, suite, key, nonce and document digest. Conditional storage claims prevent reuse for different bytes. Evidence is create-only at a deterministic S3 object path. KMS sealing is completed before reporting success; S3 and DynamoDB cannot participate in one atomic transaction. Failures may leave a processing operation, which exact retries can finish. Never turn incomplete evidence into a success response.

## Boundaries

This service proves possession/use of a policy-accepted hardware key and the associated signed bytes under the authenticated account. It does not prove legal identity, informed consent, document comprehension or legal enforceability. External JWT/email assurance belongs to the identity provider. KMS sealing is not independent timestamping. The default runtime reports timestamping unavailable. No live AWS acceptance, Android hardware verification, external audit or production readiness is established by these documents.

The document limit is 512 KiB; HTTP JSON has a 1 MiB decoded-body limit. Evidence contains sensitive original documents and identity/attestation material. Restrict S3, KMS and state access, review retention and deletion obligations, and avoid logging document/token contents. A private versioned encrypted bucket is not immutable compliance retention. No application-layer encryption negotiation, account recovery API, public evidence search or end-user key revocation endpoint is implemented.
