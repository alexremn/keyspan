# keyspan roadmap

v1.0 is 100% static file analysis (no live cloud calls): gitleaks/trufflehog
ingest, GitHub Actions + Kubernetes/ESO surfaces, correlation, four renderers, a
GitHub Action. Everything below is post-v1.0.

## v1.1 — close the cloud gap

- **CODEOWNERS team/path ownership attribution**: surface CODEOWNERS team owners
  and path-pattern ownership in the blast-radius output. v1.0 surfaces Kubernetes
  namespace ownership only; CODEOWNERS ownership is deferred to v1.1.
- **AWS IAM + Secrets Manager scanner** (the long pole): join an ESO
  `remoteRef` backend key to the real AWS secret; **AKIA** access-key-ID and ARN
  identity joins.
- **GitLab CI** scanner (`.gitlab-ci.yml` variables/`secrets:`).
- **SealedSecret**: a presence node only — keyspan can't decrypt it, so it adds
  no value edges, but it stops being invisible.

## v1.2+

- Vault / OpenBao (static config reads first).
- GCP Secret Manager, Azure Key Vault.

## Open-core (hosted)

The OSS core stays Apache-2.0; the moat is the hosted product, not the license:

- **Continuous scanning** across many repos/clusters.
- **Scan-to-scan diff + alerting** — "a new consumer started using this secret",
  "this secret's blast radius grew." The `runs` table and stable node/edge ids
  are designed into v1.0 specifically to make snapshot history cheap to add.
- Managed multi-cloud connectors and a shared dashboard.
