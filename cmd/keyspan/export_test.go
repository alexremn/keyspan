package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexremn/keyspan/internal/graph"
	"github.com/alexremn/keyspan/internal/store"
)

// exportSeedDB creates a store at path, writes a tiny graph (one secret + one
// gha consumer + a reference edge) so blast-radius/export have something to
// render, and returns the secret name used as the ref.
func exportSeedDB(t *testing.T, path string) string {
	t.Helper()
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()

	runID, err := st.BeginRun("test-seed", []string{"export_test"})
	if err != nil {
		t.Fatalf("BeginRun: %v", err)
	}

	secret := graph.Node{
		ID:    graph.NodeID(graph.NodeSecret, "aws_access_key_id"),
		Type:  graph.NodeSecret,
		Name:  "AWS_ACCESS_KEY_ID",
		Attrs: map[string]string{"surface": "finding"},
	}
	consumer := graph.Node{
		ID:    graph.NodeID(graph.NodeConsumer, "gha:.github/workflows/ci.yml#build.deploy"),
		Type:  graph.NodeConsumer,
		Name:  "gha:.github/workflows/ci.yml#build.deploy",
		Attrs: map[string]string{"surface": "gha"},
	}
	edge := graph.Edge{
		ID:         graph.EdgeID(consumer.ID, secret.ID, graph.EdgeReferences),
		Src:        consumer.ID,
		Dst:        secret.ID,
		Type:       graph.EdgeReferences,
		Direction:  graph.Directed,
		Confidence: 1.0,
		Provenance: graph.Provenance{
			RuleID:        "gha-reference",
			Evidence:      []string{"secrets.AWS_ACCESS_KEY_ID"},
			Locations:     []graph.Location{{File: ".github/workflows/ci.yml", Line: 42, Surface: "gha"}},
			MatchedTokens: []string{"AWS_ACCESS_KEY_ID"},
		},
	}
	if err := st.UpsertNode(runID, secret); err != nil {
		t.Fatalf("UpsertNode secret: %v", err)
	}
	if err := st.UpsertNode(runID, consumer); err != nil {
		t.Fatalf("UpsertNode consumer: %v", err)
	}
	if err := st.UpsertEdge(runID, edge); err != nil {
		t.Fatalf("UpsertEdge: %v", err)
	}
	return "name:AWS_ACCESS_KEY_ID"
}

func TestExportCommandAllFormatsToStdout(t *testing.T) {
	t.Cleanup(func() { flagDB = "./keyspan.db"; flagFormat = "human"; flagOut = ""; flagIncludeLocations = false; flagExportRef = "" })
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyspan.db")
	ref := exportSeedDB(t, dbPath)

	cases := []struct {
		format string
		want   string
	}{
		{"json", `"start"`},
		{"dot", "digraph keyspan {"},
		{"html", "<!DOCTYPE html>"},
		{"human", "AWS_ACCESS_KEY_ID"},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			t.Cleanup(func() { flagDB = "./keyspan.db"; flagFormat = "human"; flagOut = ""; flagIncludeLocations = false; flagExportRef = "" })
			var buf bytes.Buffer
			root := newRootCmd()
			root.SetOut(&buf)
			root.SetErr(&buf)
			root.SetArgs([]string{"export", "--db", dbPath, "--format", tc.format, "--ref", ref})
			if err := root.Execute(); err != nil {
				t.Fatalf("export --format %s: %v\noutput:\n%s", tc.format, err, buf.String())
			}
			if !strings.Contains(buf.String(), tc.want) {
				t.Fatalf("export --format %s missing %q in output:\n%s", tc.format, tc.want, buf.String())
			}
		})
	}
}

func TestExportCommandRedactsLocationsByDefault(t *testing.T) {
	t.Cleanup(func() { flagDB = "./keyspan.db"; flagFormat = "human"; flagOut = ""; flagIncludeLocations = false; flagExportRef = "" })
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyspan.db")
	ref := exportSeedDB(t, dbPath)

	// Default (no --include-locations): location JSON keys must be absent.
	// Note: consumer node name also contains "ci.yml", so check for the JSON
	// field keys ("line", "locations") rather than the path substring — same
	// pattern used in internal/render/json_test.go.
	var buf bytes.Buffer
	root := newRootCmd()
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"export", "--db", dbPath, "--format", "json", "--ref", ref})
	if err := root.Execute(); err != nil {
		t.Fatalf("export: %v", err)
	}
	if strings.Contains(buf.String(), `"line"`) || strings.Contains(buf.String(), `"locations"`) {
		t.Fatalf("locations must be redacted by default:\n%s", buf.String())
	}

	// With --include-locations: location data (line number) must appear.
	var buf2 bytes.Buffer
	root2 := newRootCmd()
	root2.SetOut(&buf2)
	root2.SetErr(&buf2)
	root2.SetArgs([]string{"export", "--db", dbPath, "--format", "json", "--ref", ref, "--include-locations"})
	if err := root2.Execute(); err != nil {
		t.Fatalf("export --include-locations: %v", err)
	}
	if !strings.Contains(buf2.String(), `"line"`) {
		t.Fatalf("locations must appear with --include-locations:\n%s", buf2.String())
	}
}

func TestExportCommandWritesToOutFile(t *testing.T) {
	t.Cleanup(func() { flagDB = "./keyspan.db"; flagFormat = "human"; flagOut = ""; flagIncludeLocations = false; flagExportRef = "" })
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyspan.db")
	ref := exportSeedDB(t, dbPath)
	outPath := filepath.Join(dir, "report.html")

	var buf bytes.Buffer
	root := newRootCmd()
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"export", "--db", dbPath, "--format", "html", "--ref", ref, "--out", outPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("export --out: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading --out file: %v", err)
	}
	if !bytes.Contains(data, []byte("<!DOCTYPE html>")) {
		t.Fatalf("--out file missing HTML doctype")
	}
}
