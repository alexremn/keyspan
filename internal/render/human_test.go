// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/alexremn/keyspan/internal/graph"
)

func humanFixtureResult() graph.QueryResult {
	start := graph.Node{ID: "s1", Type: graph.NodeSecret, Name: "AWS_ACCESS_KEY_ID"}
	consumer := graph.Node{ID: "c1", Type: graph.NodeConsumer, Name: "gha:ci.yml#build.deploy"}
	chain := []graph.Edge{{
		Type:       graph.EdgeReferences,
		Confidence: 1.0,
		Provenance: graph.Provenance{
			RuleID:    "references",
			Evidence:  []string{"workflow references secrets.AWS_ACCESS_KEY_ID"},
			Locations: []graph.Location{{File: ".github/workflows/ci.yml", Line: 20, Surface: "gha"}},
		},
	}}
	return graph.QueryResult{
		Start:   start,
		Cluster: []graph.Node{start},
		Consumers: []graph.ConsumerHit{{
			Node:       consumer,
			Confidence: 1.0,
			Band:       graph.BandHigh,
			Chain:      chain,
		}},
	}
}

func TestHumanRenderTreeShowsConsumerAndBand(t *testing.T) {
	// Arrange
	r := &humanRenderer{}
	var buf bytes.Buffer

	// Act
	if err := r.Render(&buf, humanFixtureResult(), Options{}); err != nil {
		t.Fatalf("Render: %v", err)
	}

	// Assert
	out := buf.String()
	if !strings.Contains(out, "AWS_ACCESS_KEY_ID") {
		t.Fatalf("expected start secret name in output:\n%s", out)
	}
	if !strings.Contains(out, "gha:ci.yml#build.deploy") {
		t.Fatalf("expected consumer name in output:\n%s", out)
	}
	if !strings.Contains(out, "high") {
		t.Fatalf("expected band 'high' in output:\n%s", out)
	}
	if !strings.Contains(out, "references") {
		t.Fatalf("expected one-line provenance ruleID in output:\n%s", out)
	}
}

func TestHumanRenderOmitsLocationsByDefault(t *testing.T) {
	// Arrange
	r := &humanRenderer{}
	var buf bytes.Buffer

	// Act
	if err := r.Render(&buf, humanFixtureResult(), Options{}); err != nil {
		t.Fatalf("Render: %v", err)
	}

	// Assert: redaction-safe default omits File:Line
	if strings.Contains(buf.String(), ".github/workflows/ci.yml") {
		t.Fatalf("locations must be omitted unless IncludeLocations is set:\n%s", buf.String())
	}
}

func TestHumanRenderShowsLocationsWhenRequested(t *testing.T) {
	// Arrange
	r := &humanRenderer{}
	var buf bytes.Buffer

	// Act
	if err := r.Render(&buf, humanFixtureResult(), Options{IncludeLocations: true}); err != nil {
		t.Fatalf("Render: %v", err)
	}

	// Assert
	out := buf.String()
	if !strings.Contains(out, ".github/workflows/ci.yml:20") {
		t.Fatalf("expected File:Line when IncludeLocations set:\n%s", out)
	}
}
