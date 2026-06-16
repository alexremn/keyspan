// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/alexremn/keyspan/internal/graph"
)

// renderTestFixtureResult builds a small QueryResult shared by the P6 renderer
// tests: one start secret, one correlated secret, one consumer hit with a
// location-bearing chain edge and an owner.
func renderTestFixtureResult() graph.QueryResult {
	start := graph.Node{
		ID:          graph.NodeID(graph.NodeSecret, "aws_access_key_id"),
		Type:        graph.NodeSecret,
		Name:        "AWS_ACCESS_KEY_ID",
		Fingerprint: "deadbeefdeadbeefdeadbeefdeadbeef",
		Attrs:       map[string]string{"surface": "finding"},
	}
	other := graph.Node{
		ID:    graph.NodeID(graph.NodeSecret, "aws-access-key-id"),
		Type:  graph.NodeSecret,
		Name:  "aws-access-key-id",
		Attrs: map[string]string{},
	}
	consumer := graph.Node{
		ID:    graph.NodeID(graph.NodeConsumer, "gha:.github/workflows/ci.yml#build.deploy"),
		Type:  graph.NodeConsumer,
		Name:  "gha:.github/workflows/ci.yml#build.deploy",
		Attrs: map[string]string{"surface": "gha"},
	}
	owner := graph.Node{
		ID:    graph.NodeID(graph.NodeOwner, "team:@org/sre"),
		Type:  graph.NodeOwner,
		Name:  "team:@org/sre",
		Attrs: map[string]string{},
	}
	chainEdge := graph.Edge{
		ID:         graph.EdgeID(consumer.ID, start.ID, graph.EdgeReferences),
		Src:        consumer.ID,
		Dst:        start.ID,
		Type:       graph.EdgeReferences,
		Direction:  graph.Directed,
		Confidence: 1.0,
		Provenance: graph.Provenance{
			RuleID:   "gha-reference",
			Evidence: []string{"secrets.AWS_ACCESS_KEY_ID"},
			Locations: []graph.Location{
				{File: ".github/workflows/ci.yml", Line: 42, Surface: "gha"},
			},
			MatchedTokens: []string{"AWS_ACCESS_KEY_ID"},
		},
	}
	return graph.QueryResult{
		Start:   start,
		Cluster: []graph.Node{start, other},
		Consumers: []graph.ConsumerHit{
			{
				Node:       consumer,
				Confidence: 0.90,
				Band:       graph.BandHigh,
				Chain:      []graph.Edge{chainEdge},
				Owners:     []graph.Node{owner},
			},
		},
	}
}

func TestRenderJSONStableSchemaAndRedaction(t *testing.T) {
	res := renderTestFixtureResult()

	var buf bytes.Buffer
	if err := (jsonRenderer{}).Render(&buf, res, Options{IncludeLocations: false}); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}

	// Stable top-level schema keys.
	for _, key := range []string{"start", "cluster", "consumers"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("missing top-level key %q in JSON output: %s", key, buf.String())
		}
	}

	// Fingerprints are NEVER rendered (§10).
	if bytes.Contains(buf.Bytes(), []byte("deadbeefdeadbeefdeadbeefdeadbeef")) {
		t.Fatalf("fingerprint must never appear in JSON output: %s", buf.String())
	}

	// Locations omitted when IncludeLocations is false (default redaction-safe).
	// Check for the "line" JSON key (only present in jsonLocation) and the
	// "locations" key itself; note the consumer node name also contains "ci.yml"
	// so we check for the JSON field key rather than the path substring.
	if bytes.Contains(buf.Bytes(), []byte("\"line\"")) || bytes.Contains(buf.Bytes(), []byte("\"locations\"")) {
		t.Fatalf("locations must be omitted when IncludeLocations=false: %s", buf.String())
	}
}

func TestRenderJSONIncludesLocationsWhenEnabled(t *testing.T) {
	res := renderTestFixtureResult()

	var buf bytes.Buffer
	if err := (jsonRenderer{}).Render(&buf, res, Options{IncludeLocations: true}); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	if !bytes.Contains(buf.Bytes(), []byte(".github/workflows/ci.yml")) {
		t.Fatalf("file location must appear when IncludeLocations=true: %s", buf.String())
	}
	if !bytes.Contains(buf.Bytes(), []byte("42")) {
		t.Fatalf("line number must appear when IncludeLocations=true: %s", buf.String())
	}
}
