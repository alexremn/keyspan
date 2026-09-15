# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.5] - 2026-09-15

### Changed

- Dependency refresh: `modernc.org/sqlite` 1.53.0 → 1.58.0 (with `modernc.org/libc`
  1.75.6 and `modernc.org/memory` 1.12.1), `github.com/mattn/go-isatty` 0.0.22 →
  0.0.24, `golang.org/x/sys` 0.47.0. No schema or behavior change: the committed
  `examples/outputs/` reproduce byte-for-byte and all six release targets build.
- CI/release workflows: `actions/setup-go` v7, `anchore/sbom-action` 0.24.2.

## [1.0.4] - 2026-06-25

### Changed

- GitHub Actions are referenced by semver tag instead of commit SHA so Dependabot
  can track them. Bumped `actions/checkout` v7, `actions/setup-go` v6,
  `golangci/golangci-lint-action` v9 (golangci-lint v2), `goreleaser/goreleaser-action` v7.
- `github.com/spf13/cobra` 1.10.2, `github.com/mattn/go-isatty` 0.0.22,
  `modernc.org/sqlite` 1.53.0.

### Fixed

- Lint findings surfaced by golangci-lint v2 (gofmt alignment, unused parameter).

## [1.0.3] - 2026-06-21

### Fixed

- First release built from the now-public repository, so the build-provenance
  attestation succeeds. 1.0.2 introduced the attestation but failed to persist
  it while the repo was private (GitHub gates attestation storage to public
  user repos). `brew install alexremn/tap/keyspan`, `go install`, and release
  asset downloads also require the public repo.

## [1.0.2] - 2026-06-21

### Changed

- SLSA build provenance is now produced by GitHub's
  `actions/attest-build-provenance` instead of `slsa-github-generator`, whose
  v2.1.0 reusable workflow (the latest release) is broken on current runners and
  never attached a provenance asset (1.0.0 and 1.0.1 shipped without it). Verify
  with `gh attestation verify <archive> --repo alexremn/keyspan`. cosign-signed
  checksums and the syft SBOM are unchanged.

## [1.0.1] - 2026-06-21

### Fixed

- SLSA provenance (`multiple.intoto.jsonl`) now attaches to releases. v1.0.0
  shipped without it: the SLSA generator derived the provenance name but failed
  to propagate it to the upload-assets step, so the asset never uploaded. Fixed
  by pinning `provenance-name` in the release workflow.

## [1.0.0] - 2026-06-18

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
- Homebrew cask published to `alexremn/homebrew-tap` (`brew install alexremn/tap/keyspan`).
- Human renderer now surfaces Kubernetes namespace ownership (`owners:` line) per
  consumer when present. CODEOWNERS team/path ownership attribution is planned for
  v1.1.

[Unreleased]: https://github.com/alexremn/keyspan/compare/v1.0.5...HEAD
[1.0.5]: https://github.com/alexremn/keyspan/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/alexremn/keyspan/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/alexremn/keyspan/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/alexremn/keyspan/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/alexremn/keyspan/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/alexremn/keyspan/releases/tag/v1.0.0
