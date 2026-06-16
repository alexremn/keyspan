// SPDX-License-Identifier: Apache-2.0

// internal/graph/graph_test.go
package graph

import "testing"

func graphMkNode(id string, t NodeType) Node {
	return Node{ID: id, Type: t, Name: id, Attrs: map[string]string{}}
}

func graphMkEdge(src, dst string, t EdgeType) Edge {
	return Edge{ID: EdgeID(src, dst, t), Src: src, Dst: dst, Type: t, Direction: Directed, Confidence: 1.0}
}

func TestGraphAddNodeAndLookup(t *testing.T) {
	g := New()
	n := graphMkNode("n1", NodeSecret)
	g.AddNode(n)

	got, ok := g.Node("n1")
	if !ok {
		t.Fatal("Node(n1) not found after AddNode")
	}
	if got.Type != NodeSecret {
		t.Errorf("got type %q, want secret", got.Type)
	}
	if _, ok := g.Node("missing"); ok {
		t.Error("Node(missing) should not be found")
	}
}

func TestGraphAddNodeOverwritesByID(t *testing.T) {
	g := New()
	g.AddNode(Node{ID: "n1", Type: NodeSecret, Name: "old", Attrs: map[string]string{}})
	g.AddNode(Node{ID: "n1", Type: NodeSecret, Name: "new", Attrs: map[string]string{}})

	got, _ := g.Node("n1")
	if got.Name != "new" {
		t.Errorf("AddNode should overwrite: got name %q, want new", got.Name)
	}
	if len(g.Nodes()) != 1 {
		t.Errorf("Nodes() len = %d, want 1 after re-add", len(g.Nodes()))
	}
}

func TestGraphNodesAndEdgesEnumerate(t *testing.T) {
	g := New()
	g.AddNode(graphMkNode("a", NodeSecret))
	g.AddNode(graphMkNode("b", NodeConsumer))
	g.AddEdge(graphMkEdge("b", "a", EdgeReferences))

	if len(g.Nodes()) != 2 {
		t.Errorf("Nodes() len = %d, want 2", len(g.Nodes()))
	}
	if len(g.Edges()) != 1 {
		t.Errorf("Edges() len = %d, want 1", len(g.Edges()))
	}
}

func TestGraphAddEdgeDedupesByID(t *testing.T) {
	g := New()
	g.AddNode(graphMkNode("a", NodeSecret))
	g.AddNode(graphMkNode("b", NodeConsumer))
	g.AddEdge(graphMkEdge("b", "a", EdgeReferences))
	g.AddEdge(graphMkEdge("b", "a", EdgeReferences))

	if len(g.Edges()) != 1 {
		t.Errorf("Edges() len = %d, want 1 after duplicate AddEdge", len(g.Edges()))
	}
}

func TestGraphOutAndInEdges(t *testing.T) {
	g := New()
	g.AddNode(graphMkNode("a", NodeSecret))
	g.AddNode(graphMkNode("b", NodeConsumer))
	g.AddNode(graphMkNode("c", NodeConsumer))
	g.AddEdge(graphMkEdge("b", "a", EdgeReferences))
	g.AddEdge(graphMkEdge("c", "a", EdgeInjects))

	out := g.OutEdges("b")
	if len(out) != 1 || out[0].Dst != "a" {
		t.Errorf("OutEdges(b) = %+v, want one edge to a", out)
	}
	in := g.InEdges("a")
	if len(in) != 2 {
		t.Errorf("InEdges(a) len = %d, want 2", len(in))
	}
	if len(g.OutEdges("a")) != 0 {
		t.Error("OutEdges(a) should be empty")
	}
}
