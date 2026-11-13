# Sworn Ink verification service

Go/AWS verification for Android hardware-backed biometric document signatures. External JWT authentication identifies accounts; strict Android attestation, single-use challenges and sealed evidence bind keys to exact signed bytes.

**Development source only.** No published release, public endpoint, Android hardware acceptance or live AWS validation is claimed.

- [English integration manual](docs/agents/index.md) · [Manual en español](docs/es/index.md)
- [Authoritative shared protocol](docs/agents/protocol.md) · [HTTP API](docs/agents/api.md)
- [Build and integrate](docs/agents/quickstart.md) · [Installation facts](IMPORT.md)
- [Android companion Development branch](https://github.com/lambdawalker/android.apexfission.signature/tree/feat/sworn-ink-signatures)
- [AWS inventory](docs/agents/operations.md) · [Deployment tooling](docs/deployment.md)
- [Protocol test vectors and runnable tests](protocol/protocol_test.go) · [Service examples in tests](service/service_test.go)

The module declares Go 1.27.3. Run `go test -race ./...`, `go vet ./...` and `GOOS=linux GOARCH=arm64 go build -o build/bootstrap ./cmd/api`. Infrastructure and deployment tooling are separate Go modules: run their tests from `infra/` and `cmd/deploy/`.

Build the human HTML site with `python3 sites/build.py --check` (Python 3.11+, standard library only), then `python3 -m http.server 8000 --directory sites/dist`. Open `http://localhost:8000`. The HTML and version-scoped raw Markdown are generated from the guides above. No hosted documentation URL is advertised before a successful manual Pages deployment.

[AI integration entry](AI_INTEGRATION_GUIDE.md) describes consumer retrieval; [AGENTS.md](AGENTS.md) is for repository contributors.

## Composer feature

Standalone deployment uses the importable Composer feature and native factory. See [Attestra integration](docs/composer-integration.md). Test the separate native module with `cd infrastructure && go test -race ./... && go vet ./...`. No cloud migration is implied.
