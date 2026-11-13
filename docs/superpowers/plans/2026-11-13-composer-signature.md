# Signature Composer implementation plan

Goal: Prepare signature for Attestra while making standalone deployment use Composer.
Architecture: Keep protocol/runtime unchanged; expose root feature/artifact metadata and a separate native infrastructure module. The standalone program composes the same implementation.
User approved proceeding. Attestra changes and cloud deployment are outside this branch.

- [x] Add JWT trust requirement and signature API offering, with missing/incompatible/test-provider tests.
- [x] Extract native deployment and existing security mocks; expose bounded factory forwarding dependency/secret options.
- [x] Compose standalone deployment preserving names and exports.
- [x] Document artifact building, host wiring and migration limits.
- [x] Verify race tests, vet, ARM64 build and documentation across all modules.

Review focus: absent identity fails; production rejects test defaults; native outputs remain typed; standalone names/boundary stay stable; wire protocol and security remain unchanged.
