// internal/correlate/fingerprint.go
package correlate

import (
	"sort"

	"github.com/alexremn/keyspan/internal/graph"
)

// fingerprintMatch correlates two Secret nodes that share a non-empty
// value-fingerprint. Fingerprints are salted HMAC hashes (never raw values),
// so MatchedTokens carries hashes only. Highest-confidence rule (0.95).
type fingerprintMatch struct{}

func (fingerprintMatch) ID() string { return "fingerprint-match" }

func (r fingerprintMatch) Apply(g *graph.Graph) []graph.Edge {
	// Bucket Secret nodes by their non-empty fingerprint.
	byFP := map[string][]graph.Node{}
	for _, n := range g.Nodes() {
		if n.Type != graph.NodeSecret || n.Fingerprint == "" {
			continue
		}
		byFP[n.Fingerprint] = append(byFP[n.Fingerprint], n)
	}

	var edges []graph.Edge
	for fp, nodes := range byFP {
		if len(nodes) < 2 {
			continue
		}
		// Deterministic ordering so emitted edges are stable across runs.
		sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
		for i := 0; i < len(nodes); i++ {
			for j := i + 1; j < len(nodes); j++ {
				edges = append(edges, r.edge(nodes[i], nodes[j], fp))
			}
		}
	}
	return edges
}

func (r fingerprintMatch) edge(a, b graph.Node, fp string) graph.Edge {
	return graph.Edge{
		ID:         graph.EdgeID(a.ID, b.ID, graph.EdgeCorrelates),
		Src:        a.ID,
		Dst:        b.ID,
		Type:       graph.EdgeCorrelates,
		Direction:  graph.Undirected,
		Confidence: graph.ConfFingerprintMatch,
		Provenance: graph.Provenance{
			RuleID:        r.ID(),
			Evidence:      []string{"shared value-fingerprint"},
			MatchedTokens: []string{fp},
		},
	}
}
