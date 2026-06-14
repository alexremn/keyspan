# keyspan — Tech Spec

> An OSS secret blast-radius graph: scans repos, CI configs, k8s/ESO manifests, and cloud IAM to answer "what breaks if I rotate this credential, and who owns it?" in seconds.

## Problem

When a credential leaks, tracing every consumer has no OSS tooling — documented as an 18-hour weekend incident to map one key's blast radius. 47% of non-human identities (NHIs) are over a year old and never rotated because nobody knows where they're used.

## Target user

Incident responders and platform/SRE teams at small-to-mid orgs with secrets split across AWS Secrets Manager + Vault/OpenBao + Kubernetes + CI, who can't afford GitGuardian/Entro.

## The wedge

A purely static, read-only graph keyed on the **secret/identity** as the node, correlating the same credential across surfaces. The cheapest, most demoable differentiator no OSS tool has: **ingest gitleaks/trufflehog findings as graph entry points** — closing the detection → "now what" gap. Lead with that bridge.

### Why existing tools fall short

- TruffleHog / Gitleaks — stop at detection, build no consumer map.
- GUAC / attack-maps — artifact/attack-path, not secret-to-consumer.
- External Secrets Operator — centralizes storage but (per CNCF) decentralizes ownership.
- **Honest flag:** commercial side is crowding in — Safeguard.sh pitches a near-identical consumption graph; Entro/Astrix/Token Security validate the concept. The OSS / self-hosted / read-only niche is still unoccupied.

## Stack & form factor

- **Language:** Go
- **Parsers:** GitHub/GitLab workflows, Kubernetes + ESO/SealedSecrets CRDs, AWS IAM / Secrets Manager
- **Scope v1 to ONE stack** (recommend: GitHub Actions + k8s/ESO + AWS) with conservative, confidence-scored edges
- **Storage:** SQLite-backed graph
- **Form factor:** CLI primary + optional GitHub Action that posts a blast-radius comment

## Effort to v1

- **6–8 weeks** (optimistic) — realistic only if scoped to a single stack with confidence-scored edges. Cross-surface correlation is the long pole.

## Adoption risk

Cross-surface correlation is heuristic; a false join at 2 AM kills trust. Make per-edge confidence scoring and "show your work" provenance a first-class v1 feature, not a footnote. The moat (free, self-hosted, no-SaaS) is real but thin — a vendor open-sourcing a community edition would erode it. Note: the pain is documented mostly by vendors who profit from it — pressure-test demand with real practitioners first.

## Monetization angle

OSS core; open-core hosted continuous-scan + diff/alerting dashboard and managed multi-cloud connectors.

## Verdict (from market scan)

need **4/5**, buildable **3/5** — **refine**. Ranked **#3 to build first**. Cut scope to one stack; lead the entire value prop with the gitleaks/trufflehog ingestion bridge.
