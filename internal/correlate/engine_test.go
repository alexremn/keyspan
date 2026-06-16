// SPDX-License-Identifier: Apache-2.0

// internal/correlate/engine_test.go
package correlate

import (
	"testing"

	"github.com/alexremn/keyspan/internal/graph"
)

func TestCorrelateEngineRulesOrder(t *testing.T) {
	// Arrange / Act
	rules := Rules(Options{AggressiveNames: false})

	// Assert: all three rules present, in declared order.
	if len(rules) != 3 {
		t.Fatalf("got %d rules, want 3", len(rules))
	}
	wantIDs := []string{"fingerprint-match", "reference-chain", "name-match"}
	for i, id := range wantIDs {
		if rules[i].ID() != id {
			t.Errorf("rules[%d].ID() = %q, want %q", i, rules[i].ID(), id)
		}
	}
}

func TestCorrelateRunsAllRules(t *testing.T) {
	// Arrange: one fingerprint pair + one name pair (disjoint sets).
	g := graph.New()
	g.AddNode(secretNode(t, "fp-a", "11111111111111111111111111111111"))
	g.AddNode(secretNode(t, "fp-b", "11111111111111111111111111111111"))
	g.AddNode(secretNode(t, "MY_TOKEN", ""))
	g.AddNode(secretNode(t, "my-token", ""))

	// Act
	edges := Correlate(g, Options{AggressiveNames: false})

	// Assert: one fingerprint-match (0.95) + one name-match (0.55).
	var fpCount, nameCount int
	for _, e := range edges {
		switch e.Provenance.RuleID {
		case "fingerprint-match":
			fpCount++
		case "name-match":
			nameCount++
		}
	}
	if fpCount != 1 {
		t.Errorf("fingerprint-match edges = %d, want 1", fpCount)
	}
	if nameCount != 1 {
		t.Errorf("name-match edges = %d, want 1", nameCount)
	}
}

func TestCorrelateDedupByEdgeID(t *testing.T) {
	// Arrange: a pair that BOTH fingerprint-match and name-match would join.
	// fingerprint-match (0.95, first) must win the dedup; name-match (0.55) drops.
	g := graph.New()
	g.AddNode(secretNode(t, "dup-token", "22222222222222222222222222222222"))
	g.AddNode(secretNode(t, "dup_token", "22222222222222222222222222222222"))

	// Act
	edges := Correlate(g, Options{AggressiveNames: false})

	// Assert: exactly one edge for the pair; the winner is fingerprint-match.
	if len(edges) != 1 {
		t.Fatalf("got %d edges, want 1 (deduped by EdgeID)", len(edges))
	}
	if edges[0].Provenance.RuleID != "fingerprint-match" {
		t.Errorf("dedup winner = %q, want fingerprint-match (first rule wins)", edges[0].Provenance.RuleID)
	}
}

func TestCorrelateAggressiveOption(t *testing.T) {
	// Arrange: prefixed names that only join when AggressiveNames is true.
	build := func() *graph.Graph {
		g := graph.New()
		g.AddNode(secretNode(t, "prod_api_key", ""))
		g.AddNode(secretNode(t, "api_key", ""))
		return g
	}

	// Act
	off := Correlate(build(), Options{AggressiveNames: false})
	on := Correlate(build(), Options{AggressiveNames: true})

	// Assert
	if len(off) != 0 {
		t.Errorf("aggressive-off edges = %d, want 0", len(off))
	}
	if len(on) != 1 {
		t.Errorf("aggressive-on edges = %d, want 1", len(on))
	}
}
