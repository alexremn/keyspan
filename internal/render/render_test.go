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
	// Arrange + Act + Assert: html exists but is not implemented in P6.
	for _, format := range []string{"html"} {
		_, err := New(format)
		if err == nil {
			t.Fatalf("New(%q) expected not-implemented error, got nil", format)
		}
		if !strings.Contains(err.Error(), "not implemented") {
			t.Fatalf("New(%q) error = %q, want 'not implemented'", format, err.Error())
		}
	}
}

func TestRenderNewDOTSucceeds(t *testing.T) {
	// dot now implemented in P6.
	if r, err := New("dot"); err != nil || r == nil {
		t.Fatalf("New(\"dot\") should succeed after P6, got r=%v err=%v", r, err)
	}
}

func TestRenderNewJSONSucceeds(t *testing.T) {
	// json now implemented in P6.
	if r, err := New("json"); err != nil || r == nil {
		t.Fatalf("New(\"json\") should succeed after P6, got r=%v err=%v", r, err)
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
