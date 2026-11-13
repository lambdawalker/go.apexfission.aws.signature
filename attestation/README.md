# Android hardware attestation policy

`Verifier.Verify` accepts leaf-first DER including the complete verified path,
ending at an explicitly trusted operator-supplied root. Configure `Policy.Roots`
with reviewed Google Android hardware attestation root certificates. There are
no built-in roots, system trust, downloaded roots, or trust-on-first-use.
Operators must independently verify Google's published root fingerprints and
maintain an overlapping root bundle during Google's root rotations; request
certificates never modify that bundle. Root rotation is an operations prerequisite,
not an automatic network trust update.

Set `AppPackage`, the nonempty SHA-256 `AppSignerDigests` allowlist, and
`Revocations: NewGoogleRevocations(nil)`. Nonces are exactly 32 bytes. The only
supported suites are `ES256_TEE` and `ES256_STRONGBOX`; both attestation and
keymaster security levels must match the negotiated suite.

The parser rejects malformed DER, duplicate or unordered authorization tags,
unknown tags, software-enforced required security fields, extra cryptographic
purposes/digests, non-generated keys, password authorization, auth timeouts,
no-auth, all-applications, and unlocked/unverified boot. Tag 709 app identity may
be software enforced, as Android specifies. The identity must contain exactly
one package matching the policy, and every presented signer digest must be
allowlisted. Shared-UID multi-package identities are intentionally unsupported.
Attestation version 3+ (with boot hash) and keymaster version 3+ are required.
An extension on a chain ancestor is rejected to prevent a forged descendant
certificate from substituting an application-controlled attestation record.

Revocation checks cover every certificate, including the verified trust anchor.
The fixed endpoint is `https://android.googleapis.com/attestation/status`.
Redirects, non-200 responses, malformed/duplicate JSON, unknown entry statuses,
oversized bodies, missing/stale HTTP Date, and fetch failures fail closed.
Revoked and suspended entries are both denied. A synchronized in-memory cache
is fresh for at most five minutes, shortened by Date, Age and Cache-Control.
Stale entries are never used after refresh failure. A supplied HTTP client is
operator configuration; it must preserve ordinary HTTPS certificate verification.
The constructor enforces a maximum ten-second request timeout and refuses
redirects regardless of the supplied client's redirect policy.

The signed-chain tests use freshly generated synthetic ECDSA CAs and authentic
X.509 signatures, not real Google device attestations. Parser fuzz seeds and
negative cases do not prove device-level biometric behavior. Real-device
instrumentation/manual tests remain mandatory before deployment. In particular,
this verifier does not claim that attestation explicitly proves Android's
biometric enrollment invalidation flag, nor legal identity or enforceability.

Schema and status format references (official Google implementation):
- https://github.com/google/android-key-attestation/blob/master/src/main/java/com/google/android/attestation/ParsedAttestationRecord.java
- https://github.com/google/android-key-attestation/blob/master/src/main/java/com/google/android/attestation/AuthorizationList.java
- https://github.com/google/android-key-attestation/blob/master/src/main/java/com/google/android/attestation/RootOfTrust.java
- https://github.com/google/android-key-attestation/blob/master/src/main/java/com/google/android/attestation/CertificateRevocationStatus.java

This reference repository is archived. Future Android schema changes and Google
root/status publication changes require operator review and policy updates.
