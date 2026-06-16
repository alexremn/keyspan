# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Findings ingest for gitleaks and trufflehog reports (graph entry points).
- GitHub Actions scanner: `secrets.*` references, one `env:` indirection hop,
  CODEOWNERS ownership.
- Kubernetes / ESO scanner: `injects`/`mounts`/`pulls` edges, `ExternalSecret`
  pivot, multi-doc YAML.
- Correlation engine: `fingerprint-match` (0.95), `reference-chain` (0.90),
  `name-match` (0.55), confidence bands, `--min-confidence`, `--aggressive-names`.
- Renderers: human tree, JSON, DOT, self-contained HTML (vendored Cytoscape.js),
  redaction-safe defaults.
- GitHub Action: masked-by-default PR comment with a public-repo guard.
- SQLite storage with salted fingerprints, `0600` DB, schema versioning.
- Release pipeline: cosign-signed checksums, SLSA provenance, syft SBOM.

[Unreleased]: https://github.com/alexremn/keyspan/commits/main
