// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/alexremn/keyspan/internal/graph"
	"github.com/alexremn/keyspan/internal/normalize"
)

func TestScanTrufflehogBasicEmitsFindingSecretEdge(t *testing.T) {
	// Arrange
	ing := NewTrufflehogIngester([]byte("test-salt"))

	// Act
	nodes, edges, err := ing.Ingest(context.Background(), "testdata/trufflehog/basic.jsonl")
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	// Assert
	if ing.Name() != "trufflehog" {
		t.Fatalf("Name = %q, want trufflehog", ing.Name())
	}
	finding, ok := scanFindFinding(nodes)
	if !ok {
		t.Fatalf("no finding node emitted: %+v", nodes)
	}
	wantID := graph.NodeID(graph.NodeFinding, "trufflehog:config/prod.env:12:AWS")
	if finding.ID != wantID {
		t.Fatalf("finding ID = %q, want %q", finding.ID, wantID)
	}
	if len(edges) != 1 || edges[0].Type != graph.EdgeDetectedAs {
		t.Fatalf("want 1 detected_as edge, got %+v", edges)
	}
}

func TestScanTrufflehogWithRawFingerprintsAndDiscards(t *testing.T) {
	// Arrange
	salt := []byte("test-salt")
	ing := NewTrufflehogIngester(salt)

	// Act
	nodes, edges, err := ing.Ingest(context.Background(), "testdata/trufflehog/with_raw.jsonl")
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	// Assert
	secret, ok := scanFindSecret(nodes)
	if !ok {
		t.Fatalf("no secret node emitted")
	}
	if secret.Fingerprint != normalize.Fingerprint(salt, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("fingerprint mismatch: %q", secret.Fingerprint)
	}
	blob, err := json.Marshal(struct {
		N []graph.Node
		E []graph.Edge
	}{nodes, edges})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(blob, []byte("AKIAIOSFODNN7EXAMPLE")) {
		t.Fatalf("raw secret value leaked into emitted nodes/edges")
	}
}

func TestScanTrufflehogMalformedLineSkipped(t *testing.T) {
	// Arrange
	ing := NewTrufflehogIngester([]byte("s"))

	// Act
	nodes, _, err := ing.Ingest(context.Background(), "testdata/trufflehog/malformed.jsonl")
	if err != nil {
		t.Fatalf("Ingest must tolerate malformed lines, got: %v", err)
	}

	// Assert: two valid lines survive
	count := 0
	for _, n := range nodes {
		if n.Type == graph.NodeFinding {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("want 2 findings after skipping malformed line, got %d", count)
	}
}
