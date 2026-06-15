// internal/graph/graph.go
// SPDX-License-Identifier: Apache-2.0

package graph

// Graph is an in-memory node/edge store with adjacency indexes.
type Graph struct {
	nodes map[string]Node
	edges map[string]Edge
	out   map[string][]string // node id -> edge ids where node is Src
	in    map[string][]string // node id -> edge ids where node is Dst
}

// New returns an empty Graph.
func New() *Graph {
	return &Graph{
		nodes: map[string]Node{},
		edges: map[string]Edge{},
		out:   map[string][]string{},
		in:    map[string][]string{},
	}
}

// AddNode inserts or overwrites a node by its ID.
func (g *Graph) AddNode(n Node) {
	g.nodes[n.ID] = n
}

// AddEdge inserts an edge by its ID; duplicate IDs are overwritten, not appended.
func (g *Graph) AddEdge(e Edge) {
	if _, exists := g.edges[e.ID]; !exists {
		g.out[e.Src] = append(g.out[e.Src], e.ID)
		g.in[e.Dst] = append(g.in[e.Dst], e.ID)
	}
	g.edges[e.ID] = e
}

// Node returns the node with the given id and whether it exists.
func (g *Graph) Node(id string) (Node, bool) {
	n, ok := g.nodes[id]
	return n, ok
}

// Nodes returns all nodes in unspecified order.
func (g *Graph) Nodes() []Node {
	out := make([]Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		out = append(out, n)
	}
	return out
}

// Edges returns all edges in unspecified order.
func (g *Graph) Edges() []Edge {
	out := make([]Edge, 0, len(g.edges))
	for _, e := range g.edges {
		out = append(out, e)
	}
	return out
}

// OutEdges returns edges whose Src is id.
func (g *Graph) OutEdges(id string) []Edge {
	ids := g.out[id]
	out := make([]Edge, 0, len(ids))
	for _, eid := range ids {
		out = append(out, g.edges[eid])
	}
	return out
}

// InEdges returns edges whose Dst is id.
func (g *Graph) InEdges(id string) []Edge {
	ids := g.in[id]
	out := make([]Edge, 0, len(ids))
	for _, eid := range ids {
		out = append(out, g.edges[eid])
	}
	return out
}
