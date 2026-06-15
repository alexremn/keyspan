// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/alexremn/keyspan/internal/graph"
	"github.com/alexremn/keyspan/internal/normalize"
)

// truffleResult is the subset of a trufflehog JSON-lines result keyspan reads.
// Raw/RawV2 are fingerprinted then discarded — they are NEVER persisted.
type truffleResult struct {
	DetectorName   string `json:"DetectorName"`
	Raw            string `json:"Raw"`
	RawV2          string `json:"RawV2"`
	SourceMetadata struct {
		Data struct {
			Filesystem struct {
				File string `json:"file"`
				Line int    `json:"line"`
			} `json:"Filesystem"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
}

type truffleIngester struct {
	salt []byte
}

// NewTrufflehogIngester returns an Ingester for trufflehog JSON-lines reports.
func NewTrufflehogIngester(salt []byte) Ingester {
	return &truffleIngester{salt: salt}
}

func (t *truffleIngester) Name() string { return "trufflehog" }

func (t *truffleIngester) Ingest(_ context.Context, reportPath string) ([]graph.Node, []graph.Edge, error) {
	f, err := os.Open(reportPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open trufflehog report: %w", err)
	}
	defer f.Close()

	var nodes []graph.Node
	var edges []graph.Edge
	sc := bufio.NewScanner(f)
	// trufflehog lines can be long (RawV2 inline); allow up to 4 MiB.
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	idx := -1
	for sc.Scan() {
		idx++
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec truffleResult
		if err := json.Unmarshal(line, &rec); err != nil {
			log.Printf("keyspan: skipping trufflehog record file=%s index=%d error-type=invalid-json",
				reportPath, idx)
			continue
		}
		fs := rec.SourceMetadata.Data.Filesystem
		if fs.File == "" || rec.DetectorName == "" {
			log.Printf("keyspan: skipping trufflehog record file=%s index=%d error-type=missing-required-field",
				reportPath, idx)
			continue
		}
		fNode, sNode, edge := t.recordToGraph(rec)
		nodes = append(nodes, fNode, sNode)
		edges = append(edges, edge)
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan trufflehog report: %w", err)
	}
	return nodes, edges, nil
}

func (t *truffleIngester) recordToGraph(rec truffleResult) (graph.Node, graph.Node, graph.Edge) {
	fs := rec.SourceMetadata.Data.Filesystem
	locID := fmt.Sprintf("%s:%d:%s", fs.File, fs.Line, rec.DetectorName)
	findingID := graph.NodeID(graph.NodeFinding, "trufflehog:"+locID)
	finding := graph.Node{
		ID:   findingID,
		Type: graph.NodeFinding,
		Name: rec.DetectorName,
		Attrs: map[string]string{
			"tool":     "trufflehog",
			"file":     fs.File,
			"line":     fmt.Sprintf("%d", fs.Line),
			"detector": rec.DetectorName,
		},
	}

	raw := rec.Raw
	if raw == "" {
		raw = rec.RawV2
	}
	secretKey := "fp:trufflehog:" + locID
	var fingerprint string
	if raw != "" {
		fingerprint = normalize.Fingerprint(t.salt, raw)
		secretKey = "fp:" + fingerprint
	}
	secretID := graph.NodeID(graph.NodeSecret, secretKey)
	secret := graph.Node{
		ID:          secretID,
		Type:        graph.NodeSecret,
		Name:        rec.DetectorName,
		Fingerprint: fingerprint,
		Attrs:       map[string]string{"source": "trufflehog"},
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
			Evidence:  []string{fmt.Sprintf("trufflehog detector %q at %s:%d", rec.DetectorName, fs.File, fs.Line)},
			Locations: []graph.Location{{File: fs.File, Line: fs.Line, Surface: "trufflehog"}},
		},
	}
	return finding, secret, edge
}
