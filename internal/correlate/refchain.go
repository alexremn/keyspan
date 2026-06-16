// SPDX-License-Identifier: Apache-2.0

// internal/correlate/refchain.go
package correlate

import (
	"sort"

	"github.com/alexremn/keyspan/internal/graph"
)

// referenceChain correlates a backend store Secret (keyed store:<key>, surfaced
// by an ExternalSecret) with the consuming side of the pivot k8s Secret it
// materializes (§6):
//
//	store Secret  <--references--  ExternalSecret  --syncs-->  pivot k8s Secret  <--injects/mounts--  workload
//
// The pivot k8s Secret is the shared node. The emitted correlates edge joins the
// store Secret to the pivot Secret; the pivot id is recorded in provenance.
// Confidence 0.90 (High): structural chain, not a fuzzy guess.
type referenceChain struct{}

func (referenceChain) ID() string { return "reference-chain" }

func (r referenceChain) Apply(g *graph.Graph) []graph.Edge {
	var edges []graph.Edge
	seen := map[string]bool{}

	for _, pivot := range g.Nodes() {
		if pivot.Type != graph.NodeSecret {
			continue
		}
		// A pivot must be both materialized by an ExternalSecret (incoming syncs)
		// and consumed by a workload (incoming injects/mounts/pulls).
		stores := r.storesFor(g, pivot)
		if len(stores) == 0 || !r.hasWorkloadConsumer(g, pivot) {
			continue
		}
		// Deterministic order over the joined store secrets.
		sort.Strings(stores)
		for _, storeID := range stores {
			if storeID == pivot.ID {
				continue
			}
			key := graph.EdgeID(storeID, pivot.ID, graph.EdgeCorrelates)
			if seen[key] {
				continue
			}
			seen[key] = true
			edges = append(edges, r.edge(storeID, pivot))
		}
	}
	return edges
}

// storesFor returns the ids of store Secret nodes referenced by every
// ExternalSecret consumer that syncs the pivot.
func (referenceChain) storesFor(g *graph.Graph, pivot graph.Node) []string {
	var stores []string
	for _, in := range g.InEdges(pivot.ID) {
		if in.Type != graph.EdgeSyncs {
			continue
		}
		eso := in.Src
		for _, out := range g.OutEdges(eso) {
			if out.Type != graph.EdgeReferences {
				continue
			}
			n, ok := g.Node(out.Dst)
			if ok && n.Type == graph.NodeSecret {
				stores = append(stores, n.ID)
			}
		}
	}
	return stores
}

// hasWorkloadConsumer reports whether any workload injects/mounts/pulls the pivot.
func (referenceChain) hasWorkloadConsumer(g *graph.Graph, pivot graph.Node) bool {
	for _, in := range g.InEdges(pivot.ID) {
		switch in.Type {
		case graph.EdgeInjects, graph.EdgeMounts, graph.EdgePulls:
			return true
		}
	}
	return false
}

func (r referenceChain) edge(storeID string, pivot graph.Node) graph.Edge {
	return graph.Edge{
		ID:         graph.EdgeID(storeID, pivot.ID, graph.EdgeCorrelates),
		Src:        storeID,
		Dst:        pivot.ID,
		Type:       graph.EdgeCorrelates,
		Direction:  graph.Undirected,
		Confidence: graph.ConfReferenceChain,
		Provenance: graph.Provenance{
			RuleID:        r.ID(),
			Evidence:      []string{"ExternalSecret syncs pivot k8s Secret consumed by a workload"},
			MatchedTokens: []string{pivot.ID},
		},
	}
}
