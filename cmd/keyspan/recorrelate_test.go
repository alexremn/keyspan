// cmd/keyspan/recorrelate_test.go
package main

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/alexremn/keyspan/internal/graph"
	"github.com/alexremn/keyspan/internal/store"
)

// seedCorrelatableGraph writes two name-matching Secret nodes to a fresh store
// WITHOUT any correlates edges, then returns the db path.
func seedCorrelatableGraph(t *testing.T) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "keyspan.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	runID, err := s.BeginRun("test-seed", []string{"seed"})
	if err != nil {
		t.Fatalf("begin run: %v", err)
	}
	mk := func(name string) graph.Node {
		return graph.Node{
			ID:    graph.NodeID(graph.NodeSecret, name),
			Type:  graph.NodeSecret,
			Name:  name,
			Attrs: map[string]string{},
		}
	}
	for _, n := range []graph.Node{mk("API_TOKEN"), mk("api-token")} {
		if err := s.UpsertNode(runID, n); err != nil {
			t.Fatalf("upsert node: %v", err)
		}
	}
	return dbPath
}

func TestRecorrelateCommandWritesCorrelations(t *testing.T) {
	// Arrange
	dbPath := seedCorrelatableGraph(t)
	flagDB = dbPath
	flagAggressiveNames = false
	t.Cleanup(func() { flagDB = "./keyspan.db" })

	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"recorrelate"})

	// Act
	if err := root.Execute(); err != nil {
		t.Fatalf("recorrelate: %v\noutput: %s", err, out.String())
	}

	// Assert: the graph now holds exactly one correlates edge.
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer s.Close()
	g, err := s.LoadGraph()
	if err != nil {
		t.Fatalf("load graph: %v", err)
	}
	var corr int
	for _, e := range g.Edges() {
		if e.Type == graph.EdgeCorrelates {
			corr++
		}
	}
	if corr != 1 {
		t.Fatalf("correlates edges after recorrelate = %d, want 1", corr)
	}
}
