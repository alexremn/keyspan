package scan

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/alexremn/keyspan/internal/graph"
	"github.com/alexremn/keyspan/internal/store"
)

func TestScanPersistIngestWritesGraphNoRawSecret(t *testing.T) {
	// Arrange
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyspan.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	ing := NewGitleaksIngester(st.Salt())

	// Act
	if err := PersistIngest(context.Background(), st, ing, "testdata/gitleaks/with_secret.json"); err != nil {
		t.Fatalf("PersistIngest: %v", err)
	}
	g, err := st.LoadGraph()
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Assert: graph round-trips a finding + secret
	var findings, secrets int
	for _, n := range g.Nodes() {
		switch n.Type {
		case graph.NodeFinding:
			findings++
		case graph.NodeSecret:
			secrets++
		}
	}
	if findings != 1 || secrets != 1 {
		t.Fatalf("want 1 finding + 1 secret, got %d/%d", findings, secrets)
	}

	// Assert: the raw DB file bytes never contain the known secret literal.
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read db: %v", err)
	}
	if bytes.Contains(raw, []byte("AKIAIOSFODNN7EXAMPLE")) {
		t.Fatalf("raw secret value leaked into the DB file")
	}
}
