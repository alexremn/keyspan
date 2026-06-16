// SPDX-License-Identifier: Apache-2.0

// internal/correlate/name.go
package correlate

import (
	"sort"

	"github.com/alexremn/keyspan/internal/graph"
	"github.com/alexremn/keyspan/internal/normalize"
)

// nameMatch correlates two Secret nodes whose names are equal under name-grade
// normalization (§6). Confidence is fixed Low (0.55); aggressive matches are
// still capped at that band. MatchedTokens carries the two raw names (names are
// references, not credential values).
type nameMatch struct {
	aggressive bool
}

func (nameMatch) ID() string { return "name-match" }

func (r nameMatch) Apply(g *graph.Graph) []graph.Edge {
	// Bucket Secret nodes by their graded name; skip nodes with an empty grade.
	byGrade := map[string][]graph.Node{}
	for _, n := range g.Nodes() {
		if n.Type != graph.NodeSecret {
			continue
		}
		grade := normalize.NameGrade(n.Name, r.aggressive)
		if grade == "" {
			continue
		}
		byGrade[grade] = append(byGrade[grade], n)
	}

	var edges []graph.Edge
	for _, nodes := range byGrade {
		if len(nodes) < 2 {
			continue
		}
		sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
		for i := 0; i < len(nodes); i++ {
			for j := i + 1; j < len(nodes); j++ {
				edges = append(edges, r.edge(nodes[i], nodes[j]))
			}
		}
	}
	return edges
}

func (r nameMatch) edge(a, b graph.Node) graph.Edge {
	return graph.Edge{
		ID:         graph.EdgeID(a.ID, b.ID, graph.EdgeCorrelates),
		Src:        a.ID,
		Dst:        b.ID,
		Type:       graph.EdgeCorrelates,
		Direction:  graph.Undirected,
		Confidence: graph.ConfNameMatch,
		Provenance: graph.Provenance{
			RuleID:        r.ID(),
			Evidence:      []string{"names match under name-grade normalization"},
			MatchedTokens: []string{a.Name, b.Name},
		},
	}
}
