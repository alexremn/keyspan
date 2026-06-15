-- internal/store/schema.sql
-- SPDX-License-Identifier: Apache-2.0

CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE runs (
  id           INTEGER PRIMARY KEY,
  started_at   TEXT NOT NULL,
  command      TEXT NOT NULL,
  tool_version TEXT NOT NULL,
  inputs       TEXT NOT NULL
);

CREATE TABLE nodes (
  id          TEXT PRIMARY KEY,
  type        TEXT NOT NULL,
  name        TEXT NOT NULL,
  fingerprint TEXT,
  attrs       TEXT NOT NULL DEFAULT '{}',
  last_run_id INTEGER NOT NULL REFERENCES runs(id)
);

CREATE TABLE edges (
  id          TEXT PRIMARY KEY,
  src         TEXT NOT NULL REFERENCES nodes(id),
  dst         TEXT NOT NULL REFERENCES nodes(id),
  type        TEXT NOT NULL,
  direction   TEXT NOT NULL,
  confidence  REAL NOT NULL,
  provenance  TEXT NOT NULL,
  last_run_id INTEGER NOT NULL REFERENCES runs(id)
);

CREATE INDEX idx_edges_src ON edges(src);
CREATE INDEX idx_edges_dst ON edges(dst);
CREATE INDEX idx_nodes_type ON nodes(type);
CREATE INDEX idx_nodes_fingerprint ON nodes(fingerprint);
