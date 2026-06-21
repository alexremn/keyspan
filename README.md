# keyspan

> If I rotate this credential, what breaks — and who owns it?

keyspan is an open-source **secret blast-radius graph**. It reads repos, CI
configs, and Kubernetes/ESO manifests, ingests secret-detection findings
(gitleaks/trufflehog) as graph entry points, and answers that one question fast,
with a **confidence score** and **structured provenance** on every cross-surface
edge.

Detection tools stop at "a secret leaked here." keyspan starts there and builds
the consumer map: which workflows reference it, which workloads mount it, who
owns them.

## Threat-honest "read-only"

keyspan never mutates your secrets, infra, or cloud state and makes no
authenticated API calls in v1.0 — it only **reads** local files. It **does**
write local artifacts (a SQLite graph DB and report files). Those artifacts
enumerate secret names, consumers, and locations, so they are themselves
sensitive: keyspan stores salted **fingerprints, never raw values**, writes the
DB `0600`, and redacts locations by default. See [SECURITY.md](SECURITY.md).

## 60-second quickstart (reproducible from `examples/`)

```bash
go build -o keyspan ./cmd/keyspan

# 1. Ingest a gitleaks report as graph entry points
./keyspan ingest gitleaks examples/reports/gitleaks.json

# 2. Scan the demo repo (GitHub Actions + Kubernetes/ESO surfaces)
./keyspan scan examples/repo

# 3. Correlate secrets across surfaces
./keyspan recorrelate

# 4. Ask the headline question
./keyspan blast-radius name:DATABASE_PASSWORD
```

Full walkthrough: [examples/README.md](examples/README.md).

## Sample output

```text
DATABASE_PASSWORD
  identity cluster: 3 correlated secrets
  ├─ gha:.github/workflows/ci.yml#build.migrate  [high 1.00]
  │    references — gha-reference — secrets.DATABASE_PASSWORD referenced in .github/workflows/ci.yml
  ├─ prod/Deployment/api [api]  [low 0.55]
  │    injects — injects — secretKeyRef
  │    owners: prod
  ├─ prod/ExternalSecret/db-credentials  [low 0.55]
  │    references — references — spec.data[].remoteRef.key
  │    owners: prod
```

v1.0 ownership surfaces **Kubernetes namespace** owners (e.g. `prod`) reachable
via `owned_by` edges from consumer nodes. CODEOWNERS team/path ownership
attribution is a v1.1 roadmap item and is not included in the output above.

Committed samples for all formats live in
[examples/outputs/](examples/outputs/) (`blast-radius.txt`, `.json`, `.html`).

## Install

### Homebrew

```bash
brew install alexremn/tap/keyspan
```

### go install

```bash
go install github.com/alexremn/keyspan/cmd/keyspan@latest
```

### Released binaries

Download the archive for your platform from the
[Releases](https://github.com/alexremn/keyspan/releases) page, then verify it
(below) before use.

## Verify a release (cosign + SLSA)

Releases ship a `checksums.txt`, a cosign **keyless** bundle
`checksums.txt.sigstore.json`, a syft SBOM, and SLSA provenance
(`*.intoto.jsonl`).

```bash
# 1. Verify the cosign signature on the checksum file (keyless / Sigstore).
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/alexremn/keyspan/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# 2. Verify your downloaded archive's checksum is listed.
sha256sum --check --ignore-missing checksums.txt

# 3. Verify SLSA provenance for the archive.
slsa-verifier verify-artifact keyspan_<version>_linux_amd64.tar.gz \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/alexremn/keyspan
```

## CLI

```text
keyspan scan <path...>                 populate/upsert graph from GHA + k8s surfaces
keyspan ingest gitleaks <report.json>
keyspan ingest trufflehog <report.json>
keyspan recorrelate                    recompute correlation over the current graph
keyspan blast-radius <ref>             the headline query (name:<n> | fp:<h> | finding:<id>)
keyspan export --format dot|html|json [--out FILE]
keyspan version
```

Global flags: `--db PATH` (default `./keyspan.db`, mode `0600`),
`--min-confidence FLOAT` (default `0.50`), `--format human|json|dot|html`,
`--out FILE`, `--include-locations`, `--aggressive-names`,
`--fingerprint-inline`.

Exit codes: `0` ok · `1` runtime error · `2` usage / multi-match · `3` no-match.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — pipeline, domain model, storage.
- [docs/ROADMAP.md](docs/ROADMAP.md) — what's next (AWS, GitLab, open-core).
- [SECURITY.md](SECURITY.md) — disclosure, sensitive artifacts, persistence honesty.

## License

[Apache-2.0](LICENSE).
