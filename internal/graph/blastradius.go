// internal/graph/blastradius.go
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"container/heap"
	"fmt"
	"sort"
	"strings"
)

// consumerEdgeTypes are the structural edges that point Consumer/Finding -> Secret.
var consumerEdgeTypes = map[EdgeType]bool{
	EdgeReferences: true,
	EdgeInjects:    true,
	EdgeMounts:     true,
	EdgePulls:      true,
	EdgeSyncs:      true,
	EdgeDetectedAs: true,
}

// ResolveRef maps a ref to a node id. Grammar: name:<n> | fp:<h> | finding:<id> |
// bare (tried as name then fp). Returns candidates when a name is ambiguous.
func (g *Graph) ResolveRef(ref string) (string, []Node, error) {
	switch {
	case strings.HasPrefix(ref, "name:"):
		return g.resolveByName(strings.TrimPrefix(ref, "name:"))
	case strings.HasPrefix(ref, "fp:"):
		return g.resolveByFingerprint(strings.TrimPrefix(ref, "fp:"))
	case strings.HasPrefix(ref, "finding:"):
		id := strings.TrimPrefix(ref, "finding:")
		if n, ok := g.nodes[id]; ok && n.Type == NodeFinding {
			return id, nil, nil
		}
		return "", nil, fmt.Errorf("no finding node with id %q", id)
	default:
		id, cands, err := g.resolveByName(ref)
		if err == nil {
			return id, cands, nil
		}
		if len(cands) > 0 {
			return "", cands, err
		}
		return g.resolveByFingerprint(ref)
	}
}

func (g *Graph) resolveByName(name string) (string, []Node, error) {
	var matches []Node
	for _, n := range g.nodes {
		if n.Type == NodeSecret && n.Name == name {
			matches = append(matches, n)
		}
	}
	return pickOne(matches, fmt.Sprintf("name %q", name))
}

func (g *Graph) resolveByFingerprint(fp string) (string, []Node, error) {
	var matches []Node
	for _, n := range g.nodes {
		if n.Type == NodeSecret && n.Fingerprint == fp {
			matches = append(matches, n)
		}
	}
	return pickOne(matches, fmt.Sprintf("fingerprint %q", fp))
}

func pickOne(matches []Node, what string) (string, []Node, error) {
	switch len(matches) {
	case 0:
		return "", nil, fmt.Errorf("no secret matching %s", what)
	case 1:
		return matches[0].ID, nil, nil
	default:
		sort.Slice(matches, func(i, j int) bool { return matches[i].ID < matches[j].ID })
		return "", matches, fmt.Errorf("multiple secrets match %s (%d candidates)", what, len(matches))
	}
}

// pathItem is a heap entry for the widest-path (maximin) search.
type pathItem struct {
	id         string
	bottleneck float64
	index      int
}

// maxHeap orders by bottleneck descending (widest path first).
type maxHeap []*pathItem

func (h maxHeap) Len() int            { return len(h) }
func (h maxHeap) Less(i, j int) bool  { return h[i].bottleneck > h[j].bottleneck }
func (h maxHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i]; h[i].index = i; h[j].index = j }
func (h *maxHeap) Push(x any)         { it := x.(*pathItem); it.index = len(*h); *h = append(*h, it) }
func (h *maxHeap) Pop() any {
	old := *h
	n := len(old)
	it := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	return it
}

// BlastRadius builds the identity cluster via undirected correlates (widest-path),
// then collects consumers (incoming structural edges) and owners (outgoing owned_by).
// minConfidence filters cluster membership by path bottleneck (inclusive).
func (g *Graph) BlastRadius(startID string, minConfidence float64) QueryResult {
	start, ok := g.nodes[startID]
	if !ok {
		return QueryResult{}
	}

	best := g.widestPaths(startID, minConfidence)

	cluster := make([]Node, 0, len(best))
	for id := range best {
		cluster = append(cluster, g.nodes[id])
	}
	sort.Slice(cluster, func(i, j int) bool { return cluster[i].ID < cluster[j].ID })

	consumers := g.collectConsumers(best)

	return QueryResult{Start: start, Cluster: cluster, Consumers: consumers}
}

// widestPaths returns each reachable secret's best path bottleneck from startID,
// keeping only nodes whose bottleneck >= minConfidence. Cycle-safe via finalized set.
func (g *Graph) widestPaths(startID string, minConfidence float64) map[string]float64 {
	best := map[string]float64{startID: 1.0}
	finalized := map[string]bool{}

	h := &maxHeap{}
	heap.Init(h)
	heap.Push(h, &pathItem{id: startID, bottleneck: 1.0})

	for h.Len() > 0 {
		cur := heap.Pop(h).(*pathItem)
		if finalized[cur.id] {
			continue
		}
		finalized[cur.id] = true

		for _, e := range g.correlateNeighbors(cur.id) {
			nbr := otherEnd(e, cur.id)
			cand := minF(cur.bottleneck, e.Confidence)
			if cand < minConfidence {
				continue
			}
			if known, seen := best[nbr]; !seen || cand > known {
				best[nbr] = cand
				heap.Push(h, &pathItem{id: nbr, bottleneck: cand})
			}
		}
	}
	return best
}

// correlateNeighbors returns undirected correlate edges touching id (either end).
func (g *Graph) correlateNeighbors(id string) []Edge {
	var out []Edge
	for _, eid := range g.out[id] {
		if e := g.edges[eid]; e.Type == EdgeCorrelates {
			out = append(out, e)
		}
	}
	for _, eid := range g.in[id] {
		if e := g.edges[eid]; e.Type == EdgeCorrelates {
			out = append(out, e)
		}
	}
	return out
}

func otherEnd(e Edge, id string) string {
	if e.Src == id {
		return e.Dst
	}
	return e.Src
}

// collectConsumers walks incoming structural edges of every cluster secret to reach
// Consumer/Finding nodes, attaching the cluster bottleneck as path confidence.
func (g *Graph) collectConsumers(cluster map[string]float64) []ConsumerHit {
	hits := map[string]*ConsumerHit{}

	for secretID, bottleneck := range cluster {
		for _, e := range g.InEdges(secretID) {
			if !consumerEdgeTypes[e.Type] {
				continue
			}
			cnode, ok := g.nodes[e.Src]
			if !ok {
				continue
			}
			existing, seen := hits[cnode.ID]
			if seen && existing.Confidence >= bottleneck {
				continue
			}
			hits[cnode.ID] = &ConsumerHit{
				Node:       cnode,
				Confidence: bottleneck,
				Band:       BandOf(bottleneck),
				Chain:      []Edge{e},
				Owners:     g.ownersOf(cnode.ID),
			}
		}
	}

	out := make([]ConsumerHit, 0, len(hits))
	for _, h := range hits {
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].Node.Name < out[j].Node.Name
	})
	return out
}

// ownersOf follows outgoing owned_by edges from id to Owner nodes.
func (g *Graph) ownersOf(id string) []Node {
	var owners []Node
	for _, e := range g.OutEdges(id) {
		if e.Type != EdgeOwnedBy {
			continue
		}
		if o, ok := g.nodes[e.Dst]; ok {
			owners = append(owners, o)
		}
	}
	sort.Slice(owners, func(i, j int) bool { return owners[i].Name < owners[j].Name })
	return owners
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
