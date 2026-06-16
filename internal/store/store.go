// SPDX-License-Identifier: Apache-2.0

// Package store persists the keyspan graph to SQLite.
package store

import (
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/alexremn/keyspan/internal/graph"
	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

// schemaVersion is the expected PRAGMA user_version for this build.
const schemaVersion = 1

// saltBytes is the length of the per-DB HMAC salt (256-bit).
const saltBytes = 32

// toolVersion is recorded in the runs table; overridden by the binary at wiring time.
const toolVersion = "dev"

// Store wraps a SQLite-backed keyspan graph database.
type Store struct {
	db   *sql.DB
	salt []byte
}

// Open opens (or initializes) the keyspan DB at path. It enforces 0600 perms,
// WAL/FK/busy-timeout pragmas, single-writer, schema versioning, and a per-DB salt.
func Open(path string) (*Store, error) {
	if err := ensureFile(path); err != nil {
		return nil, err
	}

	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)

	if err := initSchema(db); err != nil {
		db.Close()
		return nil, err
	}

	salt, err := loadOrCreateSalt(db)
	if err != nil {
		db.Close()
		return nil, err
	}

	return &Store{db: db, salt: salt}, nil
}

// ensureFile creates the DB file with 0600 if it does not exist, else fixes perms.
func ensureFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("create db file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close db file: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod db file: %w", err)
	}
	return nil
}

// initSchema checks PRAGMA user_version: 0 -> create schema + set 1; 1 -> ok;
// anything else -> refuse with a --rebuild hint.
func initSchema(db *sql.DB) error {
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}
	switch version {
	case 0:
		if _, err := db.Exec(schemaSQL); err != nil {
			return fmt.Errorf("create schema: %w", err)
		}
		if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
			return fmt.Errorf("set user_version: %w", err)
		}
		return nil
	case schemaVersion:
		return nil
	default:
		return fmt.Errorf("db schema version %d != expected %d; recreate with --rebuild", version, schemaVersion)
	}
}

// loadOrCreateSalt reads meta.db_salt, generating + storing it on first init.
func loadOrCreateSalt(db *sql.DB) ([]byte, error) {
	var hexSalt string
	err := db.QueryRow("SELECT value FROM meta WHERE key = 'db_salt'").Scan(&hexSalt)
	switch {
	case err == sql.ErrNoRows:
		raw := make([]byte, saltBytes)
		if _, rerr := rand.Read(raw); rerr != nil {
			return nil, fmt.Errorf("generate salt: %w", rerr)
		}
		hexSalt = hex.EncodeToString(raw)
		now := time.Now().UTC().Format(time.RFC3339)
		if _, ierr := db.Exec(
			"INSERT INTO meta(key, value) VALUES ('db_salt', ?), ('created_at', ?), ('tool_version', ?)",
			hexSalt, now, toolVersion,
		); ierr != nil {
			return nil, fmt.Errorf("store meta: %w", ierr)
		}
		return raw, nil
	case err != nil:
		return nil, fmt.Errorf("read salt: %w", err)
	default:
		raw, derr := hex.DecodeString(hexSalt)
		if derr != nil {
			return nil, fmt.Errorf("decode salt: %w", derr)
		}
		return raw, nil
	}
}

// Salt returns the per-DB HMAC salt.
func (s *Store) Salt() []byte { return s.salt }

// BeginRun records a scan/ingest invocation and returns its run id.
func (s *Store) BeginRun(command string, inputs []string) (int64, error) {
	payload, err := json.Marshal(inputs)
	if err != nil {
		return 0, fmt.Errorf("marshal inputs: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(
		"INSERT INTO runs(started_at, command, tool_version, inputs) VALUES (?, ?, ?, ?)",
		now, command, toolVersion, string(payload),
	)
	if err != nil {
		return 0, fmt.Errorf("insert run: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("run id: %w", err)
	}
	return id, nil
}

// UpsertNode inserts or replaces a node by id.
func (s *Store) UpsertNode(runID int64, n graph.Node) error {
	attrs, err := json.Marshal(orEmptyMap(n.Attrs))
	if err != nil {
		return fmt.Errorf("marshal attrs: %w", err)
	}
	_, err = s.db.Exec(`
		INSERT INTO nodes(id, type, name, fingerprint, attrs, last_run_id)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			type=excluded.type, name=excluded.name,
			fingerprint=excluded.fingerprint, attrs=excluded.attrs,
			last_run_id=excluded.last_run_id`,
		n.ID, string(n.Type), n.Name, nullable(n.Fingerprint), string(attrs), runID,
	)
	if err != nil {
		return fmt.Errorf("upsert node %s: %w", n.ID, err)
	}
	return nil
}

// UpsertEdge inserts or replaces an edge by id; FK enforcement rejects orphans.
func (s *Store) UpsertEdge(runID int64, e graph.Edge) error {
	prov, err := json.Marshal(e.Provenance)
	if err != nil {
		return fmt.Errorf("marshal provenance: %w", err)
	}
	_, err = s.db.Exec(`
		INSERT INTO edges(id, src, dst, type, direction, confidence, provenance, last_run_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			src=excluded.src, dst=excluded.dst, type=excluded.type,
			direction=excluded.direction, confidence=excluded.confidence,
			provenance=excluded.provenance, last_run_id=excluded.last_run_id`,
		e.ID, e.Src, e.Dst, string(e.Type), string(e.Direction), e.Confidence, string(prov), runID,
	)
	if err != nil {
		return fmt.Errorf("upsert edge %s: %w", e.ID, err)
	}
	return nil
}

// ReplaceCorrelations deletes all correlates edges then inserts the supplied set.
func (s *Store) ReplaceCorrelations(runID int64, edges []graph.Edge) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec("DELETE FROM edges WHERE type = ?", string(graph.EdgeCorrelates)); err != nil {
		return fmt.Errorf("clear correlates: %w", err)
	}
	for _, e := range edges {
		prov, merr := json.Marshal(e.Provenance)
		if merr != nil {
			return fmt.Errorf("marshal provenance: %w", merr)
		}
		if _, err := tx.Exec(`
			INSERT INTO edges(id, src, dst, type, direction, confidence, provenance, last_run_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			e.ID, e.Src, e.Dst, string(e.Type), string(e.Direction), e.Confidence, string(prov), runID,
		); err != nil {
			return fmt.Errorf("insert correlate %s: %w", e.ID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit correlates: %w", err)
	}
	return nil
}

// LoadGraph reads all nodes and edges into an in-memory graph.
func (s *Store) LoadGraph() (*graph.Graph, error) {
	g := graph.New()

	nodeRows, err := s.db.Query("SELECT id, type, name, fingerprint, attrs FROM nodes")
	if err != nil {
		return nil, fmt.Errorf("query nodes: %w", err)
	}
	defer nodeRows.Close()
	for nodeRows.Next() {
		var id, typ, name, attrs string
		var fp sql.NullString
		if err := nodeRows.Scan(&id, &typ, &name, &fp, &attrs); err != nil {
			return nil, fmt.Errorf("scan node: %w", err)
		}
		m := map[string]string{}
		if err := json.Unmarshal([]byte(attrs), &m); err != nil {
			return nil, fmt.Errorf("unmarshal attrs for %s: %w", id, err)
		}
		g.AddNode(graph.Node{ID: id, Type: graph.NodeType(typ), Name: name, Fingerprint: fp.String, Attrs: m})
	}
	if err := nodeRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate nodes: %w", err)
	}

	edgeRows, err := s.db.Query("SELECT id, src, dst, type, direction, confidence, provenance FROM edges")
	if err != nil {
		return nil, fmt.Errorf("query edges: %w", err)
	}
	defer edgeRows.Close()
	for edgeRows.Next() {
		var id, src, dst, typ, dir, prov string
		var conf float64
		if err := edgeRows.Scan(&id, &src, &dst, &typ, &dir, &conf, &prov); err != nil {
			return nil, fmt.Errorf("scan edge: %w", err)
		}
		var p graph.Provenance
		if err := json.Unmarshal([]byte(prov), &p); err != nil {
			return nil, fmt.Errorf("unmarshal provenance for %s: %w", id, err)
		}
		g.AddEdge(graph.Edge{
			ID: id, Src: src, Dst: dst,
			Type: graph.EdgeType(typ), Direction: graph.Direction(dir),
			Confidence: conf, Provenance: p,
		})
	}
	if err := edgeRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate edges: %w", err)
	}

	return g, nil
}

// Close closes the underlying DB.
func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("close db: %w", err)
	}
	return nil
}

func orEmptyMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
