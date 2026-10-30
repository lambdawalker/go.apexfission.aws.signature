# Failures and recovery

## Authentication or policy rejection

For `401`, check that the request went through the configured API Gateway JWT authorizer with the correct HTTPS issuer and nonempty subject. For `403`, check the access-token scope. Do not bypass authorization for debugging. For `400`, compare exact statement bytes against [Protocol](protocol.md), check base64 versus base64url, DER versus JOSE signature shape, SPKI fingerprint and exact document digest. App package/signing certificate, hardware level, biometric requirements, boot state, root rotation and revocation availability can all reject an otherwise mathematically valid signature.

A biometric cancellation, lockout, missing enrolled biometric or permanently invalidated Android key is not server success. Follow the Android error lifecycle. After enrollment changes invalidate the key, obtain a new registration challenge and key instead of substituting a software key.

## Expiry and conflict

For an expired pending challenge, obtain a new challenge and biometric signature; changing the challenge changes the signed bytes. `409` can also mean a different request already claimed the challenge. Do not replace bytes or force-reset state. Account changes require challenges and keys belonging to the new exact issuer/subject pair. A `404` must not leak another account's key or be treated as proof that no evidence exists.

## Interrupted persistence

A storage/KMS/TSA failure or lost HTTP response can happen after the conditional claim. Retry the same operation with identical decoded field values, original signature and original document/chain; JSON whitespace/member order need not be identical. Service request hashing serializes the typed request, so signing again and obtaining different DER bytes is a different request. Keep recovery material securely until completion. Use bounded retry/backoff for transient errors and refresh external authentication through the issuer if necessary.

The service first looks for the deterministic `evidence/<challengeId>.json` object, creating it only if absent. An existing matching bundle may be reused, then DynamoDB completion is retried. Registration key creation and challenge completion occur conditionally together. Pending expiry is checked before claim; already claimed matching requests can finish after the original deadline while their retained state exists. State cleanup uses `ttlAt` seven days after challenge expiry, separate from the five-minute authorization deadline. AWS TTL cleanup may later remove the recovery record; retries are not guaranteed after cleanup, while S3 evidence persists. Retry promptly. DynamoDB and S3 do not provide cross-service atomicity. A processing record or object alone must not be presented as a completed signature.

If recovery keeps failing, an authorized operator should inspect challenge state, request hash, evidence object/version and dependency logs without exposing payloads or credentials. Preserve artifacts; do not manually overwrite evidence, delete locks or manufacture completion. There is no consumer status/recovery endpoint beyond retrying these POSTs and no automatic account/key recovery feature.

## Revocation and service availability

Google status retrieval is fixed to HTTPS, redirects are rejected, timeout is at most ten seconds and cache freshness at most five minutes. Network failure, malformed/stale status or revoked/suspended serial blocks verification. Restore network/service health and retry; do not disable revocation. Configured independent timestamp provider failure likewise prevents completion; no provider means explicitly `unavailable` rather than success with independent time.

## Deployment configuration recovery

If authoritative stack YAML cannot be downloaded, stop and restore the correct encrypted object and secrets-provider metadata at the existing state prefix. The tool preserves local YAML on a failed download, but its presence does not authorize continuing. Do not delete a local file merely to satisfy first-setup checks or regenerate the Pulumi passphrase, proof/signing keys or vault. An explicit remote missing-object response allows first setup only with no local YAML and `setup --approve`; an existing stack still requires its authoritative configuration. Recover the vault in its original project/environment scope and retain the original unlock secrets.

For a target mismatch, inspect the restored `aws:region`, `awsAccount` and singleton `aws:allowedAccountIds` together with selected account, region, environment, state backend and STS role. Use explicit reconfiguration with complete reviewed inputs; do not edit a local copy to bypass the provider restriction. A changed account/region is not an infrastructure migration. For boundary/trust/tag denials, inspect `oidc-plan` and involve the separate privileged bootstrap operator. Do not grant the deployment role permission to rewrite its runtime boundary or remove API tag conditions to work around a denied preview.
