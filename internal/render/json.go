// SPDX-License-Identifier: Apache-2.0

package render

import (
	"encoding/json"
	"io"

	"github.com/alexremn/keyspan/internal/graph"
)

// jsonRenderer emits the QueryResult as a stable, documented JSON schema for
// scripting and CI. Fingerprints are never emitted; File:Line locations are
// emitted only when Options.IncludeLocations is set (default redaction-safe).
type jsonRenderer struct{}

// jsonLocation mirrors graph.Location but is only populated when locations are
// included. Omitting the field entirely (not zero-valuing it) keeps redacted
// output free of any location key.
type jsonLocation struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Surface string `json:"surface"`
}

type jsonProvenance struct {
	RuleID        string         `json:"rule_id"`
	Evidence      []string       `json:"evidence"`
	Locations     []jsonLocation `json:"locations,omitempty"`
	MatchedTokens []string       `json:"matched_tokens"`
}

type jsonNode struct {
	ID    string            `json:"id"`
	Type  graph.NodeType    `json:"type"`
	Name  string            `json:"name"`
	Attrs map[string]string `json:"attrs"`
}

type jsonEdge struct {
	ID         string          `json:"id"`
	Src        string          `json:"src"`
	Dst        string          `json:"dst"`
	Type       graph.EdgeType  `json:"type"`
	Direction  graph.Direction `json:"direction"`
	Confidence float64         `json:"confidence"`
	Provenance jsonProvenance  `json:"provenance"`
}

type jsonConsumer struct {
	Node       jsonNode   `json:"node"`
	Confidence float64    `json:"confidence"`
	Band       graph.Band `json:"band"`
	Chain      []jsonEdge `json:"chain"`
	Owners     []jsonNode `json:"owners"`
}

type jsonResult struct {
	Start     jsonNode       `json:"start"`
	Cluster   []jsonNode     `json:"cluster"`
	Consumers []jsonConsumer `json:"consumers"`
}

func (jsonRenderer) Render(w io.Writer, r graph.QueryResult, opts Options) error {
	out := jsonResult{
		Start:     toJSONNode(r.Start),
		Cluster:   toJSONNodes(r.Cluster),
		Consumers: make([]jsonConsumer, 0, len(r.Consumers)),
	}
	for _, c := range r.Consumers {
		out.Consumers = append(out.Consumers, jsonConsumer{
			Node:       toJSONNode(c.Node),
			Confidence: c.Confidence,
			Band:       c.Band,
			Chain:      toJSONEdges(c.Chain, opts.IncludeLocations),
			Owners:     toJSONNodes(c.Owners),
		})
	}

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func toJSONNode(n graph.Node) jsonNode {
	attrs := n.Attrs
	if attrs == nil {
		attrs = map[string]string{}
	}
	// Fingerprint is intentionally NOT projected (§10: never rendered).
	return jsonNode{ID: n.ID, Type: n.Type, Name: n.Name, Attrs: attrs}
}

func toJSONNodes(ns []graph.Node) []jsonNode {
	out := make([]jsonNode, 0, len(ns))
	for _, n := range ns {
		out = append(out, toJSONNode(n))
	}
	return out
}

func toJSONEdges(es []graph.Edge, includeLocations bool) []jsonEdge {
	out := make([]jsonEdge, 0, len(es))
	for _, e := range es {
		prov := jsonProvenance{
			RuleID:        e.Provenance.RuleID,
			Evidence:      e.Provenance.Evidence,
			MatchedTokens: e.Provenance.MatchedTokens,
		}
		if includeLocations {
			for _, loc := range e.Provenance.Locations {
				prov.Locations = append(prov.Locations, jsonLocation{
					File: loc.File, Line: loc.Line, Surface: loc.Surface,
				})
			}
		}
		out = append(out, jsonEdge{
			ID:         e.ID,
			Src:        e.Src,
			Dst:        e.Dst,
			Type:       e.Type,
			Direction:  e.Direction,
			Confidence: e.Confidence,
			Provenance: prov,
		})
	}
	return out
}
