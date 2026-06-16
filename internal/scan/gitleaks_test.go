// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/alexremn/keyspan/internal/graph"
	"github.com/alexremn/keyspan/internal/normalize"
)

func scanFindFinding(nodes []graph.Node) (graph.Node, bool) {
	for _, n := range nodes {
		if n.Type == graph.NodeFinding {
			return n, true
		}
	}
	return graph.Node{}, false
}

func scanFindSecret(nodes []graph.Node) (graph.Node, bool) {
	for _, n := range nodes {
		if n.Type == graph.NodeSecret {
			return n, true
		}
	}
	return graph.Node{}, false
}

func TestScanGitleaksBasicEmitsFindingSecretEdge(t *testing.T) {
	// Arrange
	ing := NewGitleaksIngester([]byte("test-salt"))

	// Act
	nodes, edges, err := ing.Ingest(context.Background(), "testdata/gitleaks/basic.json")

	// Assert
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if ing.Name() != "gitleaks" {
		t.Fatalf("Name = %q, want gitleaks", ing.Name())
	}
	finding, ok := scanFindFinding(nodes)
	if !ok {
		t.Fatalf("no finding node emitted: %+v", nodes)
	}
	wantFindingID := graph.NodeID(graph.NodeFinding,
		"gitleaks:9a1b2c3d4e5f60718293a4b5c6d7e8f901234567:config/prod.env:aws-access-token:12")
	if finding.ID != wantFindingID {
		t.Fatalf("finding ID = %q, want %q", finding.ID, wantFindingID)
	}
	secret, ok := scanFindSecret(nodes)
	if !ok {
		t.Fatalf("no secret node emitted: %+v", nodes)
	}
	if secret.Fingerprint != "" {
		t.Fatalf("redacted report must yield empty fingerprint, got %q", secret.Fingerprint)
	}
	if len(edges) != 1 {
		t.Fatalf("want 1 edge, got %d", len(edges))
	}
	e := edges[0]
	if e.Type != graph.EdgeDetectedAs {
		t.Fatalf("edge type = %q, want detected_as", e.Type)
	}
	if e.Src != finding.ID || e.Dst != secret.ID {
		t.Fatalf("edge endpoints = %s->%s, want %s->%s", e.Src, e.Dst, finding.ID, secret.ID)
	}
	if e.Confidence != 1.0 {
		t.Fatalf("detected_as confidence = %v, want 1.0", e.Confidence)
	}
}

func TestScanGitleaksWithSecretFingerprintsAndDiscards(t *testing.T) {
	// Arrange
	salt := []byte("test-salt")
	ing := NewGitleaksIngester(salt)

	// Act
	nodes, edges, err := ing.Ingest(context.Background(), "testdata/gitleaks/with_secret.json")
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	// Assert: fingerprint is the HMAC of the raw value, raw value never present
	secret, ok := scanFindSecret(nodes)
	if !ok {
		t.Fatalf("no secret node emitted")
	}
	wantFP := normalize.Fingerprint(salt, "AKIAIOSFODNN7EXAMPLE")
	if secret.Fingerprint != wantFP {
		t.Fatalf("fingerprint = %q, want %q", secret.Fingerprint, wantFP)
	}

	const raw = "AKIAIOSFODNN7EXAMPLE"
	all := append([]graph.Node{}, nodes...)
	blob, err := json.Marshal(struct {
		N []graph.Node
		E []graph.Edge
	}{all, edges})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(blob, []byte(raw)) {
		t.Fatalf("raw secret value leaked into emitted nodes/edges")
	}
	if strings.Contains(blob2s(blob), "aws_key =") {
		t.Fatalf("raw Match string leaked into emitted nodes/edges")
	}
}

func blob2s(b []byte) string { return string(b) }

func TestScanGitleaksMalformedRecordSkipped(t *testing.T) {
	// Arrange
	ing := NewGitleaksIngester([]byte("s"))

	// Act
	nodes, _, err := ing.Ingest(context.Background(), "testdata/gitleaks/malformed.json")
	if err != nil {
		t.Fatalf("Ingest must tolerate malformed records, got: %v", err)
	}

	// Assert: only the one valid finding survives
	count := 0
	for _, n := range nodes {
		if n.Type == graph.NodeFinding {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("want 1 finding after skipping malformed, got %d", count)
	}
}
