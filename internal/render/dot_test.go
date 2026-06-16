package render

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderDOTDigraphStructureAndColors(t *testing.T) {
	res := renderTestFixtureResult()

	var buf bytes.Buffer
	if err := (dotRenderer{}).Render(&buf, res, Options{IncludeLocations: false}); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	out := buf.String()

	if !strings.HasPrefix(strings.TrimSpace(out), "digraph keyspan {") {
		t.Fatalf("expected digraph header, got:\n%s", out)
	}
	if !strings.Contains(out, "}") {
		t.Fatalf("expected closing brace, got:\n%s", out)
	}

	// Secret nodes colored; consumer nodes colored differently.
	if !strings.Contains(out, "fillcolor=\"#e74c3c\"") {
		t.Fatalf("expected secret fill color, got:\n%s", out)
	}
	if !strings.Contains(out, "fillcolor=\"#3498db\"") {
		t.Fatalf("expected consumer fill color, got:\n%s", out)
	}

	// Edge labeled with confidence.
	if !strings.Contains(out, "label=\"1.00\"") {
		t.Fatalf("expected edge confidence label, got:\n%s", out)
	}

	// Node label uses the human name, quoted/escaped.
	if !strings.Contains(out, "AWS_ACCESS_KEY_ID") {
		t.Fatalf("expected secret name in node label, got:\n%s", out)
	}

	// Fingerprint never rendered.
	if strings.Contains(out, "deadbeefdeadbeefdeadbeefdeadbeef") {
		t.Fatalf("fingerprint must never appear in DOT output:\n%s", out)
	}

	// Locations omitted by default.
	if strings.Contains(out, "ci.yml:42") {
		t.Fatalf("locations must be omitted when IncludeLocations=false:\n%s", out)
	}
}

func TestRenderDOTIncludesLocationOnEdgeWhenEnabled(t *testing.T) {
	res := renderTestFixtureResult()

	var buf bytes.Buffer
	if err := (dotRenderer{}).Render(&buf, res, Options{IncludeLocations: true}); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, ".github/workflows/ci.yml:42") {
		t.Fatalf("expected File:Line on edge label when IncludeLocations=true:\n%s", out)
	}
}

func TestRenderDOTEscapesQuotesInName(t *testing.T) {
	res := renderTestFixtureResult()
	res.Start.Name = `evil"name`

	var buf bytes.Buffer
	if err := (dotRenderer{}).Render(&buf, res, Options{}); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	out := buf.String()

	// The literal quote must be backslash-escaped so it cannot break the DOT
	// string token.
	if !strings.Contains(out, `evil\"name`) {
		t.Fatalf("expected escaped quote in DOT label, got:\n%s", out)
	}
}
