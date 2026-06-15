// internal/store/store_test.go
package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/alexremn/keyspan/internal/graph"
)

func storeTempDB(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "keyspan.db")
}

func storeSecretNode(name, fp string) graph.Node {
	return graph.Node{
		ID:          graph.NodeID(graph.NodeSecret, name),
		Type:        graph.NodeSecret,
		Name:        name,
		Fingerprint: fp,
		Attrs:       map[string]string{"surface": "test"},
	}
}

func storeConsumerNode(key string) graph.Node {
	return graph.Node{
		ID:    graph.NodeID(graph.NodeConsumer, key),
		Type:  graph.NodeConsumer,
		Name:  key,
		Attrs: map[string]string{},
	}
}

func TestStoreOpenCreatesFileWith0600(t *testing.T) {
	path := storeTempDB(t)
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat db: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("db perm = %o, want 600", perm)
	}
}

func TestStoreSaltStableAcrossReopen(t *testing.T) {
	path := storeTempDB(t)
	s1, err := Open(path)
	if err != nil {
		t.Fatalf("open1: %v", err)
	}
	salt1 := append([]byte(nil), s1.Salt()...)
	if len(salt1) != 32 {
		t.Fatalf("salt len = %d, want 32", len(salt1))
	}
	s1.Close()

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("open2: %v", err)
	}
	defer s2.Close()
	salt2 := s2.Salt()

	if string(salt1) != string(salt2) {
		t.Error("db salt must be stable across reopen")
	}
}

func TestStoreRoundTripNodesAndEdges(t *testing.T) {
	path := storeTempDB(t)
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	runID, err := s.BeginRun("scan", []string{"./repo"})
	if err != nil {
		t.Fatalf("BeginRun: %v", err)
	}

	secret := storeSecretNode("aws_key", "fp123")
	consumer := storeConsumerNode("gha:ci.yml#build.deploy")
	if err := s.UpsertNode(runID, secret); err != nil {
		t.Fatalf("upsert secret: %v", err)
	}
	if err := s.UpsertNode(runID, consumer); err != nil {
		t.Fatalf("upsert consumer: %v", err)
	}

	edge := graph.Edge{
		ID:         graph.EdgeID(consumer.ID, secret.ID, graph.EdgeReferences),
		Src:        consumer.ID,
		Dst:        secret.ID,
		Type:       graph.EdgeReferences,
		Direction:  graph.Directed,
		Confidence: 1.0,
		Provenance: graph.Provenance{RuleID: "structural", Evidence: []string{"references secrets.AWS_KEY"}},
	}
	if err := s.UpsertEdge(runID, edge); err != nil {
		t.Fatalf("upsert edge: %v", err)
	}

	g, err := s.LoadGraph()
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	got, ok := g.Node(secret.ID)
	if !ok {
		t.Fatal("secret not loaded")
	}
	if got.Fingerprint != "fp123" || got.Attrs["surface"] != "test" {
		t.Errorf("secret round-trip mismatch: %+v", got)
	}
	if len(g.Edges()) != 1 {
		t.Fatalf("edges loaded = %d, want 1", len(g.Edges()))
	}
	if g.Edges()[0].Provenance.RuleID != "structural" {
		t.Error("provenance did not round-trip")
	}
}

func TestStoreUpsertNodeIdempotent(t *testing.T) {
	path := storeTempDB(t)
	s, _ := Open(path)
	defer s.Close()
	runID, _ := s.BeginRun("scan", []string{"x"})

	n := storeSecretNode("dup", "")
	_ = s.UpsertNode(runID, n)
	n2 := n
	n2.Name = "dup-updated"
	if err := s.UpsertNode(runID, n2); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	g, _ := s.LoadGraph()
	if len(g.Nodes()) != 1 {
		t.Fatalf("nodes = %d, want 1 after idempotent upsert", len(g.Nodes()))
	}
	got, _ := g.Node(n.ID)
	if got.Name != "dup-updated" {
		t.Errorf("upsert did not update name: %q", got.Name)
	}
}

func TestStoreOrphanEdgeRejectedByFK(t *testing.T) {
	path := storeTempDB(t)
	s, _ := Open(path)
	defer s.Close()
	runID, _ := s.BeginRun("scan", []string{"x"})

	// Edge referencing non-existent nodes must fail foreign-key enforcement.
	orphan := graph.Edge{
		ID:        graph.EdgeID("ghost-src", "ghost-dst", graph.EdgeReferences),
		Src:       "ghost-src",
		Dst:       "ghost-dst",
		Type:      graph.EdgeReferences,
		Direction: graph.Directed,
	}
	if err := s.UpsertEdge(runID, orphan); err == nil {
		t.Fatal("expected FK violation for orphan edge, got nil")
	}
}

func TestStoreReplaceCorrelations(t *testing.T) {
	path := storeTempDB(t)
	s, _ := Open(path)
	defer s.Close()
	runID, _ := s.BeginRun("scan", []string{"x"})

	a := storeSecretNode("a", "")
	b := storeSecretNode("b", "")
	_ = s.UpsertNode(runID, a)
	_ = s.UpsertNode(runID, b)

	corr := graph.Edge{
		ID:         graph.EdgeID(a.ID, b.ID, graph.EdgeCorrelates),
		Src:        a.ID,
		Dst:        b.ID,
		Type:       graph.EdgeCorrelates,
		Direction:  graph.Undirected,
		Confidence: 0.55,
		Provenance: graph.Provenance{RuleID: "name-match"},
	}
	if err := s.ReplaceCorrelations(runID, []graph.Edge{corr}); err != nil {
		t.Fatalf("ReplaceCorrelations: %v", err)
	}

	// Replacing with an empty set must delete prior correlates only.
	if err := s.ReplaceCorrelations(runID, nil); err != nil {
		t.Fatalf("ReplaceCorrelations empty: %v", err)
	}
	g, _ := s.LoadGraph()
	for _, e := range g.Edges() {
		if e.Type == graph.EdgeCorrelates {
			t.Error("correlates edge should have been replaced/removed")
		}
	}
}

func TestStoreUserVersionMismatchErrors(t *testing.T) {
	path := storeTempDB(t)
	s, err := Open(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	s.Close()

	// Corrupt the schema version to simulate an incompatible DB.
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	if _, err := db.Exec("PRAGMA user_version = 99"); err != nil {
		t.Fatalf("bump version: %v", err)
	}
	db.Close()

	if _, err := Open(path); err == nil {
		t.Fatal("expected user_version mismatch error")
	} else if got := err.Error(); !containsRebuildHint(got) {
		t.Errorf("error %q should mention --rebuild", got)
	}
}

func containsRebuildHint(msg string) bool {
	for i := 0; i+9 <= len(msg); i++ {
		if msg[i:i+9] == "--rebuild" {
			return true
		}
	}
	return false
}
