// internal/correlate/refchain_test.go
package correlate

import (
	"testing"

	"github.com/alexremn/keyspan/internal/graph"
)

// buildRefChainGraph wires:
//
//	store Secret  --(syncs from ExternalSecret consumer)-->  pivot k8s Secret
//	workload consumer --(injects)--> pivot k8s Secret
//
// The rule must correlate the store Secret with the pivot k8s Secret (the
// consuming side), with the pivot shown in provenance.
func buildRefChainGraph(t *testing.T) (g *graph.Graph, storeID, pivotID string) {
	t.Helper()
	g = graph.New()

	storeSecret := secretNode(t, "store:prod/db-password", "")
	pivot := secretNode(t, "db-password", "")
	eso := graph.Node{
		ID:    graph.NodeID(graph.NodeConsumer, "k8s:prod/ExternalSecret/db-es"),
		Type:  graph.NodeConsumer,
		Name:  "db-es",
		Attrs: map[string]string{"surface": "k8s", "kind": "ExternalSecret"},
	}
	workload := graph.Node{
		ID:    graph.NodeID(graph.NodeConsumer, "k8s:prod/Deployment/api#api"),
		Type:  graph.NodeConsumer,
		Name:  "api",
		Attrs: map[string]string{"surface": "k8s", "kind": "Deployment"},
	}
	g.AddNode(storeSecret)
	g.AddNode(pivot)
	g.AddNode(eso)
	g.AddNode(workload)

	// ExternalSecret materializes the pivot k8s Secret, sourced from the store.
	g.AddEdge(graph.Edge{
		ID:         graph.EdgeID(eso.ID, pivot.ID, graph.EdgeSyncs),
		Src:        eso.ID,
		Dst:        pivot.ID,
		Type:       graph.EdgeSyncs,
		Direction:  graph.Directed,
		Confidence: 1.0,
		Provenance: graph.Provenance{RuleID: "scan"},
	})
	// The ExternalSecret references the backend store key as a Secret node.
	g.AddEdge(graph.Edge{
		ID:         graph.EdgeID(eso.ID, storeSecret.ID, graph.EdgeReferences),
		Src:        eso.ID,
		Dst:        storeSecret.ID,
		Type:       graph.EdgeReferences,
		Direction:  graph.Directed,
		Confidence: 1.0,
		Provenance: graph.Provenance{RuleID: "scan"},
	})
	// Workload injects the pivot k8s Secret.
	g.AddEdge(graph.Edge{
		ID:         graph.EdgeID(workload.ID, pivot.ID, graph.EdgeInjects),
		Src:        workload.ID,
		Dst:        pivot.ID,
		Type:       graph.EdgeInjects,
		Direction:  graph.Directed,
		Confidence: 1.0,
		Provenance: graph.Provenance{RuleID: "scan"},
	})

	return g, storeSecret.ID, pivot.ID
}

func TestCorrelateReferenceChainPositive(t *testing.T) {
	// Arrange
	g, storeID, pivotID := buildRefChainGraph(t)
	rule := referenceChain{}

	// Act
	edges := rule.Apply(g)

	// Assert
	if rule.ID() != "reference-chain" {
		t.Fatalf("ID = %q, want reference-chain", rule.ID())
	}
	if len(edges) != 1 {
		t.Fatalf("got %d edges, want 1", len(edges))
	}
	e := edges[0]
	if e.Confidence != graph.ConfReferenceChain {
		t.Errorf("Confidence = %v, want %v", e.Confidence, graph.ConfReferenceChain)
	}
	if graph.BandOf(e.Confidence) != graph.BandHigh {
		t.Errorf("band = %q, want high", graph.BandOf(e.Confidence))
	}
	if e.Type != graph.EdgeCorrelates || e.Direction != graph.Undirected {
		t.Errorf("type/dir = %q/%q, want correlates/undirected", e.Type, e.Direction)
	}
	// Endpoints must be the store Secret and the pivot k8s Secret.
	endpoints := map[string]bool{e.Src: true, e.Dst: true}
	if !endpoints[storeID] || !endpoints[pivotID] {
		t.Errorf("endpoints = {%s,%s}, want {%s,%s}", e.Src, e.Dst, storeID, pivotID)
	}
	if e.ID != graph.EdgeID(e.Src, e.Dst, graph.EdgeCorrelates) {
		t.Errorf("ID = %q, not canonical EdgeID", e.ID)
	}
	// Provenance must reference the pivot Secret node.
	foundPivot := false
	for _, tok := range e.Provenance.MatchedTokens {
		if tok == pivotID {
			foundPivot = true
		}
	}
	if !foundPivot {
		t.Errorf("MatchedTokens = %v, want pivot id %s", e.Provenance.MatchedTokens, pivotID)
	}
}

func TestCorrelateReferenceChainNoWorkload(t *testing.T) {
	// Arrange: ExternalSecret syncs the pivot, but NO workload consumes it →
	// no consuming side, so no correlation.
	g, _, _ := buildRefChainGraph(t)
	// Drop the injects edge by rebuilding without it.
	g2 := graph.New()
	for _, n := range g.Nodes() {
		g2.AddNode(n)
	}
	for _, e := range g.Edges() {
		if e.Type == graph.EdgeInjects {
			continue
		}
		g2.AddEdge(e)
	}
	rule := referenceChain{}

	// Act
	edges := rule.Apply(g2)

	// Assert
	if len(edges) != 0 {
		t.Fatalf("got %d edges, want 0 (no workload consumer)", len(edges))
	}
}

func TestCorrelateReferenceChainNoStore(t *testing.T) {
	// Arrange: workload injects the pivot and an ExternalSecret syncs it, but the
	// ExternalSecret references no store Secret → nothing to join the pivot to.
	g, _, _ := buildRefChainGraph(t)
	g2 := graph.New()
	for _, n := range g.Nodes() {
		// Drop the store Secret node entirely.
		if n.Name == "store:prod/db-password" {
			continue
		}
		g2.AddNode(n)
	}
	for _, e := range g.Edges() {
		if e.Type == graph.EdgeReferences {
			continue
		}
		g2.AddEdge(e)
	}
	rule := referenceChain{}

	// Act
	edges := rule.Apply(g2)

	// Assert
	if len(edges) != 0 {
		t.Fatalf("got %d edges, want 0 (no store secret)", len(edges))
	}
}
