// SPDX-License-Identifier: Apache-2.0

package security_test

import (
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/alexremn/keyspan/internal/correlate"
	"github.com/alexremn/keyspan/internal/graph"
	"github.com/alexremn/keyspan/internal/render"
	"github.com/alexremn/keyspan/internal/scan"
	"github.com/alexremn/keyspan/internal/store"
)

// knownSecret is the RAW value present in every fixture (gitleaks report, k8s
// inline Secret). The §16 invariant: it must appear in NONE of the DB bytes,
// any renderer output, any node/edge JSON, or any captured log line.
const knownSecret = "AKIAIOSFODNN7EXAMPLE"

func TestSecurityInvariantNoRawSecretAnywhere(t *testing.T) {
	// Capture ALL standard-library log output for the duration of the run.
	var logBuf bytes.Buffer
	origOut := log.Writer()
	origFlags := log.Flags()
	log.SetOutput(&logBuf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(origOut)
		log.SetFlags(origFlags)
	})

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyspan.db")
	root := "testdata"
	ctx := context.Background()

	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	salt := st.Salt()

	// 1) Ingest the gitleaks finding (raw value -> fingerprint -> discarded).
	runID, err := st.BeginRun("ingest gitleaks", []string{"testdata/gitleaks.json"})
	if err != nil {
		t.Fatalf("BeginRun ingest: %v", err)
	}
	gl := scan.NewGitleaksIngester(salt)
	nodes, edges, err := gl.Ingest(ctx, filepath.Join(root, "gitleaks.json"))
	if err != nil {
		t.Fatalf("gitleaks ingest: %v", err)
	}
	writeAll(t, st, runID, nodes, edges)

	// 2) Scan k8s + gha surfaces (with inline fingerprinting on so the inline
	//    Secret value is hashed then discarded, same invariant path).
	runID2, err := st.BeginRun("scan", []string{root})
	if err != nil {
		t.Fatalf("BeginRun scan: %v", err)
	}
	for _, sc := range scan.Scanners(scan.ScanOptions{FingerprintInline: true, Salt: salt}) {
		ns, es, err := sc.Scan(ctx, root)
		if err != nil {
			t.Fatalf("scanner %s: %v", sc.Name(), err)
		}
		writeAll(t, st, runID2, ns, es)
	}

	// 3) Correlate over the stored graph and persist correlates edges.
	g, err := st.LoadGraph()
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	corr := correlate.Correlate(g, correlate.Options{AggressiveNames: false})
	if err := st.ReplaceCorrelations(runID2, corr); err != nil {
		t.Fatalf("ReplaceCorrelations: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("store.Close: %v", err)
	}

	// 4) Reload and render ALL FOUR formats, with locations ON (the most
	//    revealing setting — the invariant must hold even then).
	st2, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer st2.Close()
	g2, err := st2.LoadGraph()
	if err != nil {
		t.Fatalf("LoadGraph reopen: %v", err)
	}

	// Resolve a secret that exists post-scan (the k8s Secret referenced via
	// secretKeyRef; node names are stored canonically). Its blast radius is
	// rendered so the invariant covers a real QueryResult, not an empty one.
	id, _, err := g2.ResolveRef("name:aws-creds")
	if err != nil {
		t.Fatalf("ResolveRef: %v", err)
	}
	result := g2.BlastRadius(id, 0.0)

	renderOutputs := map[string][]byte{}
	for _, format := range []string{"human", "json", "dot", "html"} {
		r, err := render.New(format)
		if err != nil {
			t.Fatalf("render.New(%q): %v", format, err)
		}
		var buf bytes.Buffer
		if err := r.Render(&buf, result, render.Options{IncludeLocations: true, Color: false}); err != nil {
			t.Fatalf("render %s: %v", format, err)
		}
		renderOutputs[format] = buf.Bytes()
	}

	needle := []byte(knownSecret)

	// Assert: raw secret absent from every renderer output.
	for format, out := range renderOutputs {
		if bytes.Contains(out, needle) {
			t.Errorf("raw secret leaked into %s renderer output", format)
		}
	}

	// Assert: raw secret absent from the on-disk DB bytes.
	dbBytes, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read DB file: %v", err)
	}
	if bytes.Contains(dbBytes, needle) {
		t.Errorf("raw secret leaked into the SQLite DB file bytes")
	}
	// Also check the WAL sidecar if present (writes may sit there pre-checkpoint).
	if walBytes, werr := os.ReadFile(dbPath + "-wal"); werr == nil {
		if bytes.Contains(walBytes, needle) {
			t.Errorf("raw secret leaked into the SQLite WAL file bytes")
		}
	}

	// Assert: raw secret absent from captured logs.
	if bytes.Contains(logBuf.Bytes(), needle) {
		t.Errorf("raw secret leaked into log output: %s", logBuf.String())
	}
}

func writeAll(t *testing.T, st *store.Store, runID int64, nodes []graph.Node, edges []graph.Edge) {
	t.Helper()
	for _, n := range nodes {
		if err := st.UpsertNode(runID, n); err != nil {
			t.Fatalf("UpsertNode: %v", err)
		}
	}
	for _, e := range edges {
		if err := st.UpsertEdge(runID, e); err != nil {
			t.Fatalf("UpsertEdge: %v", err)
		}
	}
}
