# Sworn Ink — Development

This Go service verifies Android hardware-backed biometric signatures and stores sealed evidence in AWS. This manual describes source on `feat/sworn-ink-signatures`; no published release or deployed endpoint is confirmed. English is canonical; Spanish covers every guide listed here. The Go repository owns the shared protocol.

## Start here

- [Quickstart](quickstart.md): build from source and follow the registration/signing flow.
- [Concepts](concepts.md): identity, key ownership, challenges and evidence.
- [Protocol](protocol.md): exact interoperable bytes.
- [HTTP API](api.md): authenticated requests and responses.
- [Recipes](recipes.md): integration and independent verification.
- [Security and limits](security.md): trust policy and unverified boundaries.
- [Troubleshooting](troubleshooting.md): safe recovery after failures.
- [Migration](migration.md): Development compatibility and future releases.
- [AWS operations](operations.md): resource inventory and operating boundaries.

## Companion and source

[Android Development documentation](https://github.com/lambdawalker/android.apexfission.signature/blob/feat/sworn-ink-signatures/docs/agents/index.md) describes the biometric UI and key lifecycle. These are coordinated Development branches; links move to retained main revisions after integration. [Go source](https://github.com/lambdawalker/go.apexfission.aws.signature/tree/feat/sworn-ink-signatures) includes executable protocol, attestation and service tests. Generated HTML and downloadable raw Markdown use these same authored guides. The generated SHA-256 manifest identifies the exact checked source bytes; it is freshness evidence, not a signature or a release claim.
