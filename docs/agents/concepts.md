# Identity and lifecycle

## Ownership

The trusted JWT authorizer supplies `issuer` and `subject`; their exact pair owns keys and challenges. Email is not an account identifier. No registration or signing body chooses an issuer. API Gateway validates issuer, audience and scopes; Lambda rejects missing authorizer claims. Direct service tests inject identities without creating an unauthenticated network mode.

## Hardware policy

Both suites use P-256 ECDSA and SHA-256. `ES256_STRONGBOX` has preference over `ES256_TEE` for registration, regardless of client order. A signing challenge keeps the registered key's suite, which must be offered. Capability reporting is advisory: attestation proves the actual hardware level. Failure after selection requires an explicit new operation; no software downgrade is allowed.

## Challenge state

A challenge has a random 32-byte nonce and five-minute validity. Registration binds a generated key to its owner. Signing binds a registered key to an exact document digest. Pending challenges expire by explicit conditions; DynamoDB TTL is asynchronous cleanup and does not authorize requests. A conditional claim binds the challenge to the request hash before evidence is written. Processing and completed retries must match that hash. Different bytes conflict.

## Evidence

The JSON envelope contains an evidence payload, KMS seal and timestamp status. The payload includes the exact statement, signature, document for signing, registration key and chain, challenge identity, verification time and policy. KMS signs SHA-256 of the payload. The signing key and evidence encryption key have distinct roles. With no independent timestamp provider, `timestamp.status` is `unavailable`; a server clock or KMS receipt is not an independent timestamp.

The service owns no background goroutines. Configure its dependencies before serving; stores, signers, attesters and timestamp providers must support concurrent calls. Request contexts carry cancellation to dependency calls. A client disconnect cannot undo an already claimed or persisted operation: use exact retries as described in [recovery](troubleshooting.md).
