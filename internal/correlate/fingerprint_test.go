// SPDX-License-Identifier: Apache-2.0

// internal/correlate/fingerprint_test.go
package correlate

import (
	"testing"

	"github.com/alexremn/keyspan/internal/graph"
)

func secretNode(t *testing.T, name, fp string) graph.Node {
	t.Helper()
	return graph.Node{
		ID:          graph.NodeID(graph.NodeSecret, name),
		Type:        graph.NodeSecret,
		Name:        name,
		Fingerprint: fp,
		Attrs:       map[string]string{},
	}
}

func TestCorrelateFingerprintMatchPositive(t *testing.T) {
	// Arrange
	g := graph.New()
	a := secretNode(t, "aws-key-a", "deadbeefdeadbeefdeadbeefdeadbeef")
	b := secretNode(t, "aws-key-b", "deadbeefdeadbeefdeadbeefdeadbeef")
	g.AddNode(a)
	g.AddNode(b)
	rule := fingerprintMatch{}

	// Act
	edges := rule.Apply(g)

	// Assert
	if rule.ID() != "fingerprint-match" {
		t.Fatalf("ID = %q, want fingerprint-match", rule.ID())
	}
	if len(edges) != 1 {
		t.Fatalf("got %d edges, want 1", len(edges))
	}
	e := edges[0]
	if e.Type != graph.EdgeCorrelates {
		t.Errorf("Type = %q, want correlates", e.Type)
	}
	if e.Direction != graph.Undirected {
		t.Errorf("Direction = %q, want undirected", e.Direction)
	}
	if e.Confidence != graph.ConfFingerprintMatch {
		t.Errorf("Confidence = %v, want %v", e.Confidence, graph.ConfFingerprintMatch)
	}
	if e.Provenance.RuleID != "fingerprint-match" {
		t.Errorf("Provenance.RuleID = %q, want fingerprint-match", e.Provenance.RuleID)
	}
	if len(e.Provenance.MatchedTokens) != 1 || e.Provenance.MatchedTokens[0] != "deadbeefdeadbeefdeadbeefdeadbeef" {
		t.Errorf("MatchedTokens = %v, want [fingerprint]", e.Provenance.MatchedTokens)
	}
	wantID := graph.EdgeID(a.ID, b.ID, graph.EdgeCorrelates)
	if e.Src == a.ID && e.Dst == b.ID {
		if e.ID != wantID {
			t.Errorf("ID = %q, want %q", e.ID, wantID)
		}
	}
}

func TestCorrelateFingerprintMatchNegative(t *testing.T) {
	// Arrange: different fingerprints + an empty-fingerprint node
	g := graph.New()
	g.AddNode(secretNode(t, "key-a", "deadbeefdeadbeefdeadbeefdeadbeef"))
	g.AddNode(secretNode(t, "key-b", "cafebabecafebabecafebabecafebabe"))
	g.AddNode(secretNode(t, "key-c", "")) // empty fp must never join
	rule := fingerprintMatch{}

	// Act
	edges := rule.Apply(g)

	// Assert
	if len(edges) != 0 {
		t.Fatalf("got %d edges, want 0", len(edges))
	}
}

func TestCorrelateFingerprintMatchEmptyShared(t *testing.T) {
	// Arrange: two nodes sharing an EMPTY fingerprint must NOT correlate
	g := graph.New()
	g.AddNode(secretNode(t, "empty-a", ""))
	g.AddNode(secretNode(t, "empty-b", ""))
	rule := fingerprintMatch{}

	// Act
	edges := rule.Apply(g)

	// Assert
	if len(edges) != 0 {
		t.Fatalf("empty fingerprints correlated: got %d edges, want 0", len(edges))
	}
}
