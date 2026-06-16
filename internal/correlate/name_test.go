// internal/correlate/name_test.go
package correlate

import (
	"testing"

	"github.com/alexremn/keyspan/internal/graph"
)

func TestCorrelateNameMatchDefaultGrade(t *testing.T) {
	// Arrange: names equal under default name-grade (lowercase + strip -_.)
	g := graph.New()
	a := secretNode(t, "AWS_ACCESS_KEY_ID", "")
	b := secretNode(t, "aws-access-key-id", "")
	g.AddNode(a)
	g.AddNode(b)
	rule := nameMatch{aggressive: false}

	// Act
	edges := rule.Apply(g)

	// Assert
	if rule.ID() != "name-match" {
		t.Fatalf("ID = %q, want name-match", rule.ID())
	}
	if len(edges) != 1 {
		t.Fatalf("got %d edges, want 1", len(edges))
	}
	e := edges[0]
	if e.Type != graph.EdgeCorrelates || e.Direction != graph.Undirected {
		t.Errorf("type/dir = %q/%q, want correlates/undirected", e.Type, e.Direction)
	}
	if e.Confidence != graph.ConfNameMatch {
		t.Errorf("Confidence = %v, want %v", e.Confidence, graph.ConfNameMatch)
	}
	if graph.BandOf(e.Confidence) != graph.BandLow {
		t.Errorf("band = %q, want low", graph.BandOf(e.Confidence))
	}
	if e.Provenance.RuleID != "name-match" {
		t.Errorf("RuleID = %q, want name-match", e.Provenance.RuleID)
	}
	if len(e.Provenance.MatchedTokens) != 2 {
		t.Errorf("MatchedTokens = %v, want both names", e.Provenance.MatchedTokens)
	}
}

func TestCorrelateNameMatchAggressiveOffKeepsDistinct(t *testing.T) {
	// Arrange: differ only by an enumerated prefix; with aggressive OFF they
	// must stay distinct (grade strips -_. but not prod_).
	g := graph.New()
	g.AddNode(secretNode(t, "prod_db_password", ""))
	g.AddNode(secretNode(t, "db_password", ""))
	rule := nameMatch{aggressive: false}

	// Act
	edges := rule.Apply(g)

	// Assert
	if len(edges) != 0 {
		t.Fatalf("aggressive-off correlated prefixed names: got %d, want 0", len(edges))
	}
}

func TestCorrelateNameMatchAggressiveOnJoins(t *testing.T) {
	// Arrange: same pair, aggressive ON strips prod_ prefix → match.
	g := graph.New()
	g.AddNode(secretNode(t, "prod_db_password", ""))
	g.AddNode(secretNode(t, "db_password", ""))
	rule := nameMatch{aggressive: true}

	// Act
	edges := rule.Apply(g)

	// Assert: still Low band even when aggressive.
	if len(edges) != 1 {
		t.Fatalf("aggressive-on did not join: got %d, want 1", len(edges))
	}
	if graph.BandOf(edges[0].Confidence) != graph.BandLow {
		t.Errorf("aggressive match band = %q, want low (capped 0.55)", graph.BandOf(edges[0].Confidence))
	}
}

func TestCorrelateNameMatchEmptyNameSkipped(t *testing.T) {
	// Arrange: a Secret keyed by fingerprint has an empty graded name; two such
	// nodes must NOT correlate by name.
	g := graph.New()
	g.AddNode(graph.Node{ID: "n1", Type: graph.NodeSecret, Name: "", Attrs: map[string]string{}})
	g.AddNode(graph.Node{ID: "n2", Type: graph.NodeSecret, Name: "  ", Attrs: map[string]string{}})
	rule := nameMatch{aggressive: false}

	// Act
	edges := rule.Apply(g)

	// Assert
	if len(edges) != 0 {
		t.Fatalf("empty graded names correlated: got %d, want 0", len(edges))
	}
}
