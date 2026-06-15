// internal/scan/codeowners.go
package scan

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/alexremn/keyspan/internal/graph"
)

const codeownersRuleID = "codeowners"

// codeownersLocations lists, in GitHub precedence order, where a CODEOWNERS file may live.
var codeownersLocations = []string{
	".github/CODEOWNERS",
	"CODEOWNERS",
	"docs/CODEOWNERS",
}

type codeownersEntry struct {
	pattern string
	owners  []string
}

// scanCodeowners locates the first CODEOWNERS file under root and emits Owner nodes
// plus owned_by edges (resource pattern -> owner). Missing file is a no-op.
func scanCodeowners(root string) ([]graph.Node, []graph.Edge, error) {
	path, ok := findCodeowners(root)
	if !ok {
		return nil, nil, nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("codeowners: read %s: %w", path, err)
	}
	entries, err := parseCodeowners(content)
	if err != nil {
		return nil, nil, fmt.Errorf("codeowners: parse %s: %w", path, err)
	}
	relpath := filepath.ToSlash(strings.TrimPrefix(path, filepath.Clean(root)+string(os.PathSeparator)))

	var nodes []graph.Node
	var edges []graph.Edge
	seenNode := map[string]bool{}
	seenEdge := map[string]bool{}

	for _, entry := range entries {
		resourceKey := "path:" + entry.pattern
		resourceID := graph.NodeID(graph.NodeConsumer, resourceKey)
		if !seenNode[resourceID] {
			seenNode[resourceID] = true
			nodes = append(nodes, graph.Node{
				ID:    resourceID,
				Type:  graph.NodeConsumer,
				Name:  resourceKey,
				Attrs: map[string]string{"surface": "codeowners", "pattern": entry.pattern},
			})
		}
		for _, raw := range entry.owners {
			kind, key := ownerKindAndKey(raw)
			ownerID := graph.NodeID(graph.NodeOwner, key)
			if !seenNode[ownerID] {
				seenNode[ownerID] = true
				nodes = append(nodes, graph.Node{
					ID:    ownerID,
					Type:  graph.NodeOwner,
					Name:  raw,
					Attrs: map[string]string{"kind": kind},
				})
			}
			edgeID := graph.EdgeID(resourceID, ownerID, graph.EdgeOwnedBy)
			if seenEdge[edgeID] {
				continue
			}
			seenEdge[edgeID] = true
			edges = append(edges, graph.Edge{
				ID:         edgeID,
				Src:        resourceID,
				Dst:        ownerID,
				Type:       graph.EdgeOwnedBy,
				Direction:  graph.Directed,
				Confidence: 1.0,
				Provenance: graph.Provenance{
					RuleID:        codeownersRuleID,
					Evidence:      []string{fmt.Sprintf("%s owns %s", raw, entry.pattern)},
					Locations:     []graph.Location{{File: relpath, Surface: "codeowners"}},
					MatchedTokens: []string{entry.pattern},
				},
			})
		}
	}
	return nodes, edges, nil
}

func findCodeowners(root string) (string, bool) {
	for _, rel := range codeownersLocations {
		candidate := filepath.Join(root, filepath.FromSlash(rel))
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, true
		}
	}
	return "", false
}

// parseCodeowners parses CODEOWNERS content into entries, skipping blanks/comments.
func parseCodeowners(content []byte) ([]codeownersEntry, error) {
	var entries []codeownersEntry
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		entries = append(entries, codeownersEntry{
			pattern: fields[0],
			owners:  fields[1:],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// ownerKindAndKey classifies a CODEOWNERS owner token and returns its kind and canonicalKey.
func ownerKindAndKey(raw string) (kind, key string) {
	switch {
	case strings.Contains(raw, "/"):
		return "team", "team:" + raw
	case strings.HasPrefix(raw, "@"):
		return "user", "user:" + raw
	default:
		return "email", "email:" + raw
	}
}
