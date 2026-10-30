# Version scope and migration

Only Development documentation is available. No confirmed releases or historical consumer manuals are recorded; the initial release archive is empty. A Git tag alone is not proof of successful publication. The `sworn-ink/v1` protocol marker names the wire contract, not a published Go module version. Do not infer a `v1.0.0` dependency from it.

For coordinated Development changes, update the authoritative [Protocol](protocol.md), Go/Android encoder fixture and negative tests together. Check statement field order, byte lengths, nonce representation, suite identifiers, DER signatures, owner binding, JSON fields and evidence policy before updating a client. New incompatible wire semantics need an explicit protocol/version strategy; there is no automatic negotiation of another protocol.

## Future release archive

The generated `catalog.json` exposes the empty release list and localized Development entry routes. Before advertising any release, record confirmed module/version/publication destination, exact consumer coordinates, immutable code commit/tag, immutable documentation identity and translation provenance. Retain every confirmed record; add reviewed corrections separately from code identity. Build all retained versions from their recorded content and fail when snapshots are missing. The current builder intentionally refuses a nonempty release catalog until historical snapshot rendering is implemented; it must not label current pages as an old release.

Current guide links remain inside the chosen language and Development scope. The language switch preserves the selected guide. Raw Markdown is available within the same scope. No fake release selector is shown for an empty archive. Installation guidance in `IMPORT.md` remains source-only until publication is verified.

## Documentation authoring

Edit `docs/agents/*.md` first, review the corresponding Spanish prose in `docs/es/*.md`, preserve executable code fences, then update only the reviewed files' canonical SHA-256 entries in `docs/es/manifest.json`. A stale/missing translation fails the build instead of silently serving mismatched content. The generated source manifest hashes implementation and authored docs on every build; generation does not attest that a human reviewed a source change.

```bash
python3 -m unittest discover -s sites -p 'test_*.py'
python3 sites/build.py --check
```

The build clears stale output and validates internal generated links. Preview at narrow/desktop widths and with keyboard/reduced-motion settings when a browser is available. HTML/link tests do not establish visual QA. GitHub Pages deployment is a separate manual main-branch workflow and publishes no packages or AWS resources.
