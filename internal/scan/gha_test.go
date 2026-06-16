// SPDX-License-Identifier: Apache-2.0

// internal/scan/gha_test.go
package scan

import (
	"context"
	"testing"

	"github.com/alexremn/keyspan/internal/graph"
	"github.com/alexremn/keyspan/internal/normalize"
)

func ghaFindEdge(edges []graph.Edge, src, dst string, t graph.EdgeType) (graph.Edge, bool) {
	for _, e := range edges {
		if e.Src == src && e.Dst == dst && e.Type == t {
			return e, true
		}
	}
	return graph.Edge{}, false
}

func ghaNodeByID(nodes []graph.Node, id string) (graph.Node, bool) {
	for _, n := range nodes {
		if n.ID == id {
			return n, true
		}
	}
	return graph.Node{}, false
}

func TestGHAScannerName(t *testing.T) {
	s := newGHAScanner()
	if got := s.Name(); got != "gha" {
		t.Fatalf("Name() = %q, want %q", got, "gha")
	}
}

func TestGHAScannerDirectSecretReference(t *testing.T) {
	// Arrange
	s := newGHAScanner()

	// Act
	nodes, edges, err := s.Scan(context.Background(), "testdata/gha/repo")
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	// Assert: consumer node for the deploy step exists, per FIXED canonicalKey form.
	relpath := ".github/workflows/ci.yml"
	consumerKey := "gha:" + relpath + "#build.deploy"
	consumerID := graph.NodeID(graph.NodeConsumer, consumerKey)
	consumer, ok := ghaNodeByID(nodes, consumerID)
	if !ok {
		t.Fatalf("consumer node %q (key %q) not found", consumerID, consumerKey)
	}
	if consumer.Type != graph.NodeConsumer {
		t.Fatalf("consumer.Type = %q, want %q", consumer.Type, graph.NodeConsumer)
	}

	// Secret node for DEPLOY_TOKEN, keyed by identity-canonical name.
	secretName := normalize.IdentityName("DEPLOY_TOKEN")
	secretID := graph.NodeID(graph.NodeSecret, secretName)
	if _, ok := ghaNodeByID(nodes, secretID); !ok {
		t.Fatalf("secret node for DEPLOY_TOKEN (id %q) not found", secretID)
	}

	// references edge Consumer -> Secret, directed, confidence 1.0.
	e, ok := ghaFindEdge(edges, consumerID, secretID, graph.EdgeReferences)
	if !ok {
		t.Fatalf("references edge %s -> %s not found", consumerID, secretID)
	}
	if e.Direction != graph.Directed {
		t.Fatalf("edge.Direction = %q, want %q", e.Direction, graph.Directed)
	}
	if e.Confidence != 1.0 {
		t.Fatalf("edge.Confidence = %v, want 1.0", e.Confidence)
	}
	if e.Provenance.RuleID != "gha-reference" {
		t.Fatalf("provenance.RuleID = %q, want %q", e.Provenance.RuleID, "gha-reference")
	}
	if len(e.Provenance.Locations) == 0 {
		t.Fatalf("expected at least one provenance location")
	}
	if e.Provenance.Locations[0].File != relpath {
		t.Fatalf("location.File = %q, want %q", e.Provenance.Locations[0].File, relpath)
	}
	if e.Provenance.Locations[0].Surface != "gha" {
		t.Fatalf("location.Surface = %q, want %q", e.Provenance.Locations[0].Surface, "gha")
	}

	// Second secret in the same step.
	awsName := normalize.IdentityName("AWS_ACCESS_KEY_ID")
	awsID := graph.NodeID(graph.NodeSecret, awsName)
	if _, ok := ghaFindEdge(edges, consumerID, awsID, graph.EdgeReferences); !ok {
		t.Fatalf("references edge to AWS_ACCESS_KEY_ID not found")
	}
}

func TestGHAScannerStepWithoutSecretsHasNoEdge(t *testing.T) {
	// Arrange
	s := newGHAScanner()

	// Act
	_, edges, err := s.Scan(context.Background(), "testdata/gha/repo")
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	// Assert: the "checkout" step references nothing, so its consumer has no references edge.
	checkoutKey := "gha:.github/workflows/ci.yml#build.checkout"
	checkoutID := graph.NodeID(graph.NodeConsumer, checkoutKey)
	for _, e := range edges {
		if e.Src == checkoutID && e.Type == graph.EdgeReferences {
			t.Fatalf("checkout step unexpectedly references a secret: %+v", e)
		}
	}
}

func TestGHAScannerEnvIndirectionOneHop(t *testing.T) {
	// Arrange
	s := newGHAScanner()

	// Act
	_, edges, err := s.Scan(context.Background(), "testdata/gha/repo")
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	consumerKey := "gha:.github/workflows/env.yml#release.publish"
	consumerID := graph.NodeID(graph.NodeConsumer, consumerKey)

	// Step-scoped env: STEP_KEY = secrets.STEP_SECRET, used via ${{ env.STEP_KEY }}.
	stepSecretID := graph.NodeID(graph.NodeSecret, normalize.IdentityName("STEP_SECRET"))
	if _, ok := ghaFindEdge(edges, consumerID, stepSecretID, graph.EdgeReferences); !ok {
		t.Fatalf("expected references edge for env-indirect STEP_SECRET")
	}

	// Job-scoped env: JOB_KEY = secrets.JOB_SECRET, used via ${{ env.JOB_KEY }}.
	jobSecretID := graph.NodeID(graph.NodeSecret, normalize.IdentityName("JOB_SECRET"))
	if _, ok := ghaFindEdge(edges, consumerID, jobSecretID, graph.EdgeReferences); !ok {
		t.Fatalf("expected references edge for env-indirect JOB_SECRET")
	}

	// Workflow-scoped env: GLOBAL_TOKEN = secrets.GLOBAL_SECRET, used via ${{ env.GLOBAL_TOKEN }}.
	globalSecretID := graph.NodeID(graph.NodeSecret, normalize.IdentityName("GLOBAL_SECRET"))
	if _, ok := ghaFindEdge(edges, consumerID, globalSecretID, graph.EdgeReferences); !ok {
		t.Fatalf("expected references edge for env-indirect GLOBAL_SECRET")
	}

	// Provenance for indirect edges names the env key (one-hop evidence).
	e, _ := ghaFindEdge(edges, consumerID, stepSecretID, graph.EdgeReferences)
	if e.Provenance.RuleID != "gha-env-indirection" {
		t.Fatalf("provenance.RuleID = %q, want %q", e.Provenance.RuleID, "gha-env-indirection")
	}
}

func TestGHAScannerEnvIndirectionUnresolvedKeyNoEdge(t *testing.T) {
	// Arrange
	s := newGHAScanner()

	// Act
	_, edges, err := s.Scan(context.Background(), "testdata/gha/repo")
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	// The "noenv" step uses ${{ env.UNDEFINED_KEY }} which maps to no secret -> no references edge.
	noenvID := graph.NodeID(graph.NodeConsumer, "gha:.github/workflows/env.yml#release.noenv")
	for _, e := range edges {
		if e.Src == noenvID && e.Type == graph.EdgeReferences {
			t.Fatalf("noenv step unexpectedly produced a references edge: %+v", e)
		}
	}
}
