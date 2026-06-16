// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/alexremn/keyspan/internal/graph"
)

// dotRenderer emits a Graphviz digraph: nodes colored by type, edges labeled
// with confidence. Fingerprints are never rendered; File:Line is appended to an
// edge label only when Options.IncludeLocations is set.
type dotRenderer struct{}

var dotFillByType = map[graph.NodeType]string{
	graph.NodeSecret:   "#e74c3c", // red
	graph.NodeConsumer: "#3498db", // blue
	graph.NodeOwner:    "#2ecc71", // green
	graph.NodeFinding:  "#f39c12", // orange
}

func (dotRenderer) Render(w io.Writer, r graph.QueryResult, opts Options) error {
	var b strings.Builder
	b.WriteString("digraph keyspan {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  node [style=filled, shape=box, fontname=\"Helvetica\"];\n")

	// Collect nodes (dedup by id) so each is declared once.
	// r.Start is collected last so its name wins over any cluster copy.
	nodes := map[string]graph.Node{}
	collect := func(n graph.Node) { nodes[n.ID] = n }
	for _, n := range r.Cluster {
		collect(n)
	}
	for _, c := range r.Consumers {
		collect(c.Node)
		for _, o := range c.Owners {
			collect(o)
		}
	}
	collect(r.Start)

	ids := make([]string, 0, len(nodes))
	for id := range nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids) // deterministic golden output

	for _, id := range ids {
		n := nodes[id]
		fill := dotFillByType[n.Type]
		if fill == "" {
			fill = "#bdc3c7"
		}
		b.WriteString("  \"" + id + "\" [label=\"" + dotEscape(n.Name) + "\", fillcolor=\"" + fill + "\"];\n")
	}

	// Edges from consumer chains.
	type edgeKey struct{ src, dst, typ string }
	seen := map[edgeKey]bool{}
	for _, c := range r.Consumers {
		for _, e := range c.Chain {
			k := edgeKey{e.Src, e.Dst, string(e.Type)}
			if seen[k] {
				continue
			}
			seen[k] = true
			label := fmt.Sprintf("%.2f", e.Confidence)
			if opts.IncludeLocations {
				if loc := firstLocation(e); loc != "" {
					label = label + "\\n" + dotEscape(loc)
				}
			}
			b.WriteString("  \"" + e.Src + "\" -> \"" + e.Dst + "\" [label=\"" + label + "\"];\n")
		}
	}

	b.WriteString("}\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// dotEscape escapes characters that would break a DOT double-quoted string.
func dotEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

func firstLocation(e graph.Edge) string {
	for _, loc := range e.Provenance.Locations {
		if loc.File != "" {
			return fmt.Sprintf("%s:%d", loc.File, loc.Line)
		}
	}
	return ""
}
