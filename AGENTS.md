# Contributor instructions

Consumer manual: [docs/agents/index.md](docs/agents/index.md). Do not use this contributor file as the API contract.

- Preserve external JWT identity as exact issuer/subject. Keep hardware, ownership, revocation, expiry and replay validation fail-closed. Never add a production authentication bypass.
- Read the approved design in `docs/superpowers/specs/2026-10-30-sworn-ink-design.md` before changing the contract. `docs/agents/protocol.md` is the authoritative shared protocol; synchronize the Android encoder/vector for any wire change.
- Run root `go test -race ./...`, `go vet ./...` and ARM64 Linux `cmd/api` build; separately test `infrastructure/`, `infra/` and `cmd/deploy/`. Use the module-declared Go toolchain.
- Edit canonical English `docs/agents/*.md`, review corresponding Spanish `docs/es/*.md`, preserve code fences and then update only reviewed source hashes in `docs/es/manifest.json`. Run the site tests and `python3 sites/build.py --check`. Do not claim visual/browser validation from a link checker.
- Generated `sites/dist/` is ignored. Never hand-edit or commit generated HTML. Keep `sites/catalog.json` empty until a release is confirmed and historical snapshot rendering is implemented. Never fabricate published coordinates or archive history.
- Deployment/publication requires explicit operator authorization. Tests must not provision resources or dispatch workflows. Never commit credentials, operator vaults, state exports or original user documents.
