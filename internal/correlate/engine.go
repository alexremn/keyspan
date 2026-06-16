// SPDX-License-Identifier: Apache-2.0

// internal/correlate/engine.go
package correlate

import "github.com/alexremn/keyspan/internal/graph"

// Rule is a single correlation heuristic. Rules share no state; each examines
// the graph and emits confidence-scored correlates edges.
type Rule interface {
	ID() string
	Apply(g *graph.Graph) []graph.Edge
}

// Options tunes correlation behavior.
type Options struct {
	AggressiveNames bool
}

// Rules returns the v1.0 rule set in priority order: highest-confidence first so
// that when two rules emit the same undirected edge (same EdgeID), the stronger
// rule wins the dedup in Correlate.
func Rules(opts Options) []Rule {
	return []Rule{
		fingerprintMatch{},
		referenceChain{},
		nameMatch{aggressive: opts.AggressiveNames},
	}
}

// Correlate runs every rule over the graph and returns the union of emitted
// correlates edges, deduplicated by EdgeID. The first rule to emit a given
// EdgeID wins (rule order in Rules is highest-confidence-first), so a pair that
// both fingerprint- and name-matches keeps the 0.95 edge.
func Correlate(g *graph.Graph, opts Options) []graph.Edge {
	seen := map[string]bool{}
	var out []graph.Edge
	for _, rule := range Rules(opts) {
		for _, e := range rule.Apply(g) {
			if seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			out = append(out, e)
		}
	}
	return out
}
