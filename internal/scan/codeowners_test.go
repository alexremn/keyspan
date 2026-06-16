// SPDX-License-Identifier: Apache-2.0

// internal/scan/codeowners_test.go
package scan

import (
	"testing"

	"github.com/alexremn/keyspan/internal/graph"
)

func codeownersNodeByID(nodes []graph.Node, id string) (graph.Node, bool) {
	for _, n := range nodes {
		if n.ID == id {
			return n, true
		}
	}
	return graph.Node{}, false
}

func TestCodeownersParseEntries(t *testing.T) {
	// Arrange
	content := []byte("# comment\n*  @org/platform\n.github/workflows/  @org/ci-team ci-bot@example.com\n")

	// Act
	entries, err := parseCodeowners(content)
	if err != nil {
		t.Fatalf("parseCodeowners() error = %v", err)
	}

	// Assert
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}
	if entries[0].pattern != "*" || len(entries[0].owners) != 1 || entries[0].owners[0] != "@org/platform" {
		t.Fatalf("entry[0] = %+v, unexpected", entries[0])
	}
	if entries[1].pattern != ".github/workflows/" {
		t.Fatalf("entry[1].pattern = %q, want %q", entries[1].pattern, ".github/workflows/")
	}
	if len(entries[1].owners) != 2 {
		t.Fatalf("entry[1].owners = %v, want 2 owners", entries[1].owners)
	}
}

func TestCodeownersOwnerKind(t *testing.T) {
	// Arrange / Act / Assert
	cases := []struct {
		raw      string
		wantKind string
		wantID   string
	}{
		{"@org/ci-team", "team", "team:@org/ci-team"},
		{"@octocat", "user", "user:@octocat"},
		{"ci-bot@example.com", "email", "email:ci-bot@example.com"},
	}
	for _, tc := range cases {
		kind, key := ownerKindAndKey(tc.raw)
		if kind != tc.wantKind || key != tc.wantID {
			t.Fatalf("ownerKindAndKey(%q) = (%q,%q), want (%q,%q)", tc.raw, kind, key, tc.wantKind, tc.wantID)
		}
	}
}

func TestCodeownersScanProducesOwnerNodesAndEdges(t *testing.T) {
	// Arrange
	root := "testdata/gha/repo"

	// Act
	nodes, edges, err := scanCodeowners(root)
	if err != nil {
		t.Fatalf("scanCodeowners() error = %v", err)
	}

	// Assert: an Owner node for @org/ci-team exists with the team-keyed id.
	ownerID := graph.NodeID(graph.NodeOwner, "team:@org/ci-team")
	ownerNode, ok := codeownersNodeByID(nodes, ownerID)
	if !ok {
		t.Fatalf("owner node for @org/ci-team (id %q) not found", ownerID)
	}
	if ownerNode.Type != graph.NodeOwner {
		t.Fatalf("owner.Type = %q, want %q", ownerNode.Type, graph.NodeOwner)
	}

	// owned_by edge: the workflows-pattern resource -> the ci-team owner, directed conf 1.0.
	var found bool
	for _, e := range edges {
		if e.Dst == ownerID && e.Type == graph.EdgeOwnedBy {
			found = true
			if e.Direction != graph.Directed {
				t.Fatalf("owned_by.Direction = %q, want %q", e.Direction, graph.Directed)
			}
			if e.Confidence != 1.0 {
				t.Fatalf("owned_by.Confidence = %v, want 1.0", e.Confidence)
			}
			if e.Provenance.RuleID != "codeowners" {
				t.Fatalf("owned_by.Provenance.RuleID = %q, want %q", e.Provenance.RuleID, "codeowners")
			}
		}
	}
	if !found {
		t.Fatalf("no owned_by edge pointing at @org/ci-team")
	}
}

func TestCodeownersScanMissingFileIsNoOp(t *testing.T) {
	// Arrange: a dir without any CODEOWNERS file.
	root := t.TempDir()

	// Act
	nodes, edges, err := scanCodeowners(root)

	// Assert
	if err != nil {
		t.Fatalf("scanCodeowners() error = %v, want nil", err)
	}
	if len(nodes) != 0 || len(edges) != 0 {
		t.Fatalf("expected empty result, got %d nodes / %d edges", len(nodes), len(edges))
	}
}
