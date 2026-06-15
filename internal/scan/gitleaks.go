// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/alexremn/keyspan/internal/graph"
	"github.com/alexremn/keyspan/internal/normalize"
)

// gitleaksFinding is the subset of a gitleaks JSON-array record keyspan reads.
// Secret/Match are only present when gitleaks runs with --no-redact; keyspan
// fingerprints them then discards — they are NEVER persisted.
type gitleaksFinding struct {
	RuleID      string `json:"RuleID"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	Commit      string `json:"Commit"`
	Fingerprint string `json:"Fingerprint"`
	Secret      string `json:"Secret"`
	Match       string `json:"Match"`
}

type gitleaksIngester struct {
	salt []byte
}

// NewGitleaksIngester returns an Ingester for gitleaks JSON-array reports.
func NewGitleaksIngester(salt []byte) Ingester {
	return &gitleaksIngester{salt: salt}
}

func (g *gitleaksIngester) Name() string { return "gitleaks" }

func (g *gitleaksIngester) Ingest(_ context.Context, reportPath string) ([]graph.Node, []graph.Edge, error) {
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read gitleaks report: %w", err)
	}
	var records []gitleaksFinding
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, nil, fmt.Errorf("decode gitleaks report (expected JSON array): %w", err)
	}

	var nodes []graph.Node
	var edges []graph.Edge
	for i, rec := range records {
		if rec.Fingerprint == "" || rec.RuleID == "" {
			// Tolerant parsing: never log the raw record (it may carry a secret).
			log.Printf("keyspan: skipping gitleaks record file=%s index=%d error-type=missing-required-field",
				reportPath, i)
			continue
		}
		fNode, sNode, edge := g.recordToGraph(rec)
		nodes = append(nodes, fNode, sNode)
		edges = append(edges, edge)
	}
	return nodes, edges, nil
}

func (g *gitleaksIngester) recordToGraph(rec gitleaksFinding) (graph.Node, graph.Node, graph.Edge) {
	findingKey := "gitleaks:" + rec.Fingerprint
	findingID := graph.NodeID(graph.NodeFinding, findingKey)
	finding := graph.Node{
		ID:   findingID,
		Type: graph.NodeFinding,
		Name: rec.RuleID,
		Attrs: map[string]string{
			"tool": "gitleaks",
			"file": rec.File,
			"line": fmt.Sprintf("%d", rec.StartLine),
			"rule": rec.RuleID,
		},
	}

	// Secret node keyed by the finding location id (no name available from gitleaks).
	secretKey := "fp:" + rec.Fingerprint
	var fingerprint string
	if rec.Secret != "" {
		// Compute the value-fingerprint, then discard the raw literal forever.
		fingerprint = normalize.Fingerprint(g.salt, rec.Secret)
		secretKey = "fp:" + fingerprint
	}
	secretID := graph.NodeID(graph.NodeSecret, secretKey)
	secret := graph.Node{
		ID:          secretID,
		Type:        graph.NodeSecret,
		Name:        rec.RuleID,
		Fingerprint: fingerprint,
		Attrs:       map[string]string{"source": "gitleaks"},
	}

	edge := graph.Edge{
		ID:         graph.EdgeID(findingID, secretID, graph.EdgeDetectedAs),
		Src:        findingID,
		Dst:        secretID,
		Type:       graph.EdgeDetectedAs,
		Direction:  graph.Directed,
		Confidence: 1.0,
		Provenance: graph.Provenance{
			RuleID:    "detected_as",
			Evidence:  []string{fmt.Sprintf("gitleaks rule %q at %s:%d", rec.RuleID, rec.File, rec.StartLine)},
			Locations: []graph.Location{{File: rec.File, Line: rec.StartLine, Surface: "gitleaks"}},
		},
	}
	return finding, secret, edge
}
