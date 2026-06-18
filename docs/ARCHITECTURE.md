# keyspan architecture

Distilled from the design spec. keyspan answers one question: *"if I rotate this
credential, what breaks — and who owns it?"* The conceptual node is the
secret/identity; edges connect the same credential across surfaces, each carrying
a confidence score and structured provenance.

## Pipeline

```
Scan/Ingest  →  Normalize  →  Correlate  →  Store(SQLite)  →  Query  →  Render
```

Each stage is a package with one responsibility and a typed boundary:

- **Scanners / Ingesters** (`internal/scan`) emit normalized `Node`/`Edge`
  records — decoupled from storage. New surface = one new scanner, zero core
  changes. Ingesters turn gitleaks/trufflehog findings into graph entry points
  (the wedge).
- **Normalizer** (`internal/normalize`) canonicalizes names (identity-grade) and
  computes salted fingerprints.
- **Correlator** (`internal/correlate`) runs independent rules, emitting
  confidence-scored `correlates` edges. Trust-critical and isolated.
- **Store** (`internal/store`) persists to SQLite — one current graph.
- **Query** (`internal/graph`) builds the identity cluster and traverses for
  blast-radius.
- **Renderers** (`internal/render`) consume a `QueryResult` — one interface,
  four formats (human/json/dot/html).

**Correlation timing:** scanners/ingesters write raw nodes + structural edges;
`correlates` edges are computed and persisted after each `scan`/`ingest`, so
`blast-radius` reads the stored graph without re-correlating. `recorrelate`
recomputes correlation over the current graph.

## Domain model

- **Node types:** `Secret`, `Consumer`, `Owner`, `Finding`. A node's id is
  `hex(SHA-256(type ∥ 0x00 ∥ canonicalKey))[:32]` — deterministic, upsert-stable.
- **Identity:** keyspan **does not physically merge** Secret nodes. The logical
  identity is the connected component of Secret nodes joined by `correlates`
  edges at/above the active confidence threshold. Merging would destroy the
  uncertainty of a confidence-scored guess and can't be undone.
- **Fingerprints:** `HMAC-SHA-256(db_salt, value)`, hex, 128-bit. The raw value
  is discarded immediately. Never persisted, never logged. (See SECURITY.md for
  the honest residual-risk statement.)
- **Edges:** `detected_as`, `references`, `injects`, `mounts`, `pulls`, `syncs`,
  `owned_by` are structural (conf 1.0, directed). `correlates` is heuristic
  (0.55–0.95, undirected). Each carries structured provenance.

## Correlation rules

| Rule | Joins on | Conf | Band |
|------|----------|------|------|
| `fingerprint-match` | shared value-fingerprint | 0.95 | High |
| `reference-chain` | ExternalSecret `syncs` → Secret ← workload `injects`/`mounts` | 0.90 | High |
| `name-match` | names match under name-grade normalization | 0.55 | Low |

**Confidence bands (half-open):** High ≥ 0.85 · Medium [0.60, 0.85) · Low < 0.60.
`--min-confidence` is an inclusive display gate (default 0.50).

## Query — blast-radius

Given a starting Secret (resolved from a `name:`/`fp:`/`finding:` ref):

1. Build the identity cluster via **widest-path (maximin)** search over
   `correlates` edges — a max-heap on the bottleneck confidence of the best path;
   keep nodes whose path bottleneck ≥ `--min-confidence`.
2. Collect consumers by following incoming structural edges (conf 1.0), so a
   consumer's path confidence equals the bottleneck of the `correlates` hops.
3. Collect owners via outgoing `owned_by` edges.
4. Attach provenance; sort by path confidence, then surface, then name.

## Storage

SQLite via `modernc.org/sqlite` (pure Go, static binary). One current graph,
upsert by stable id. Pragmas: WAL, `busy_timeout(5000)`, `foreign_keys(on)`,
`SetMaxOpenConns(1)`. File mode `0600`. `db_salt` (256-bit) lives in `meta`.
`PRAGMA user_version` is checked at open; mismatch refuses with a `--rebuild`
hint (no silent migration).

## Layout

```
cmd/keyspan/              main + cobra wiring
internal/scan/            scanners: findings, gha, k8s
internal/scan/testdata/   fixtures for scan tests (gha/, gitleaks/, trufflehog/)
internal/normalize/       identity + name-grade canonicalization, fingerprints
internal/correlate/       rules + engine
internal/graph/           node/edge model, widest-path traversal
internal/store/           SQLite schema, pragmas, read/write, versioning
internal/render/          human / json / dot / html (+ embedded cytoscape)
internal/security/        invariant tests
action/                   GitHub Action
action/testdata/          fixtures for action tests
examples/                 committed demo repo + reports + sample outputs
docs/                     this file + ROADMAP.md
```
