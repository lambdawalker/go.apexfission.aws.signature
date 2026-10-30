# Installation facts — Development

Module: `github.com/lambdawalker/go.apexfission.aws.signature`.

No successfully published version or confirmed destination coordinates are recorded. Do not invent a semantic version or recommend `@latest`. The repository has a Development source branch `feat/sworn-ink-signatures`; a branch is mutable and is not an immutable consumer pin. Select and review a retained commit explicitly when integrating Development code. No prior release documentation archive is claimed.

```bash
git clone --branch feat/sworn-ink-signatures https://github.com/lambdawalker/go.apexfission.aws.signature.git
cd go.apexfission.aws.signature
go test -race ./...
```

The module declares Go 1.26.0. `go.mod` and `go.sum` record exact dependencies. `infra/` and `cmd/deploy/` are separate operator modules, not required to import the protocol or service packages. The Android companion is separately built and has no implied shared release number.

See [Quickstart](docs/agents/quickstart.md), [API](docs/agents/api.md), [protocol](docs/agents/protocol.md) and [version policy](docs/agents/migration.md). `sites/catalog.json` is the persistent empty release catalogue; publication must be verified and historical rendering implemented before it can advertise releases.
