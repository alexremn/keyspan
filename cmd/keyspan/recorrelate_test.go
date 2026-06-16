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

// TestRecorrelateCrossSurfaceOneCluster proves the cross-surface payoff (§16):
// a secret referenced by a GHA step and mounted by a k8s workload, under
// matching names, lands in one identity cluster so blast-radius surfaces BOTH
// consumers from a single start node.
func TestRecorrelateCrossSurfaceOneCluster(t *testing.T) {
	// Arrange: two Secret nodes (GHA-named vs k8s-named, name-match joins them),
	// each with its own structural consumer, plus the consumer edges.
	dbPath := filepath.Join(t.TempDir(), "keyspan.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	runID, err := s.BeginRun("test-seed", []string{"seed"})
	if err != nil {
		t.Fatalf("begin run: %v", err)
	}

	ghaSecret := graph.Node{
		ID: graph.NodeID(graph.NodeSecret, "deploy-token"), Type: graph.NodeSecret,
		Name: "DEPLOY_TOKEN", Attrs: map[string]string{},
	}
	k8sSecret := graph.Node{
		ID: graph.NodeID(graph.NodeSecret, "deploy-token-k8s"), Type: graph.NodeSecret,
		Name: "deploy-token", Attrs: map[string]string{},
	}
	ghaStep := graph.Node{
		ID:   graph.NodeID(graph.NodeConsumer, "gha:.github/workflows/ci.yml#build.deploy"),
		Type: graph.NodeConsumer, Name: "deploy", Attrs: map[string]string{"surface": "gha"},
	}
	k8sWorkload := graph.Node{
		ID:   graph.NodeID(graph.NodeConsumer, "k8s:prod/Deployment/api#api"),
		Type: graph.NodeConsumer, Name: "api", Attrs: map[string]string{"surface": "k8s"},
	}
	for _, n := range []graph.Node{ghaSecret, k8sSecret, ghaStep, k8sWorkload} {
		if err := s.UpsertNode(runID, n); err != nil {
			t.Fatalf("upsert node: %v", err)
		}
	}
	// gha step references its secret; k8s workload mounts its secret.
	mkEdge := func(src, dst string, et graph.EdgeType) graph.Edge {
		return graph.Edge{
			ID: graph.EdgeID(src, dst, et), Src: src, Dst: dst, Type: et,
			Direction: graph.Directed, Confidence: 1.0,
			Provenance: graph.Provenance{RuleID: "scan"},
		}
	}
	for _, e := range []graph.Edge{
		mkEdge(ghaStep.ID, ghaSecret.ID, graph.EdgeReferences),
		mkEdge(k8sWorkload.ID, k8sSecret.ID, graph.EdgeMounts),
	} {
		if err := s.UpsertEdge(runID, e); err != nil {
			t.Fatalf("upsert edge: %v", err)
		}
	}
	s.Close()

	flagDB = dbPath
	flagAggressiveNames = false
	flagMinConfidence = 0.50
	t.Cleanup(func() { flagDB = "./keyspan.db"; flagMinConfidence = 0.50 })

	// Act: recorrelate, then blast-radius from the GHA-named secret.
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"recorrelate"})
	if err := root.Execute(); err != nil {
		t.Fatalf("recorrelate: %v\n%s", err, out.String())
	}

	s2, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	g, err := s2.LoadGraph()
	if err != nil {
		t.Fatalf("load graph: %v", err)
	}

	// Assert: blast-radius from the GHA secret reaches BOTH consumers in one cluster.
	res := g.BlastRadius(ghaSecret.ID, flagMinConfidence)
	if len(res.Cluster) != 2 {
		t.Fatalf("cluster size = %d, want 2 (both Secret nodes correlated)", len(res.Cluster))
	}
	surfaces := map[string]bool{}
	for _, c := range res.Consumers {
		surfaces[c.Node.Attrs["surface"]] = true
	}
	if !surfaces["gha"] || !surfaces["k8s"] {
		t.Fatalf("consumer surfaces = %v, want both gha and k8s in one cluster", surfaces)
	}
}
