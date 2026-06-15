package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/alexremn/keyspan/internal/graph"
)

func TestRenderNewHumanSucceeds(t *testing.T) {
	// Arrange
	r, err := New("human")
	if err != nil {
		t.Fatalf("New(human): %v", err)
	}

	// Act
	var buf bytes.Buffer
	err = r.Render(&buf, graph.QueryResult{Start: graph.Node{Name: "x"}}, Options{})

	// Assert
	if err != nil {
		t.Fatalf("human Render: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatalf("human renderer produced no output")
	}
}

func TestRenderNewNotImplementedFormats(t *testing.T) {
	// Arrange + Act + Assert: json/dot/html exist but are not implemented in P2.
	for _, format := range []string{"json", "dot", "html"} {
		_, err := New(format)
		if err == nil {
			t.Fatalf("New(%q) expected not-implemented error, got nil", format)
		}
		if !strings.Contains(err.Error(), "not implemented") {
			t.Fatalf("New(%q) error = %q, want 'not implemented'", format, err.Error())
		}
	}
}

func TestRenderNewUnknownFormat(t *testing.T) {
	// Arrange + Act
	_, err := New("yaml")

	// Assert
	if err == nil {
		t.Fatalf("New(yaml) expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown format") {
		t.Fatalf("New(yaml) error = %q, want 'unknown format'", err.Error())
	}
}
