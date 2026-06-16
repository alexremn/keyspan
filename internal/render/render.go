// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"io"

	"github.com/alexremn/keyspan/internal/graph"
)

// Options control rendering output. IncludeLocations gates File:Line redaction;
// Color enables ANSI styling for TTY output.
type Options struct {
	IncludeLocations bool
	Color            bool
}

// Renderer turns a QueryResult into a formatted report.
type Renderer interface {
	Render(w io.Writer, r graph.QueryResult, opts Options) error
}

// New returns a Renderer for the named format. In phase 2 only "human" is
// implemented; json/dot/html are recognized but report not-implemented; any
// other value is an unknown format.
func New(format string) (Renderer, error) {
	switch format {
	case "human":
		return &humanRenderer{}, nil
	case "json":
		return jsonRenderer{}, nil
	case "dot":
		return dotRenderer{}, nil
	case "html":
		return nil, fmt.Errorf("%q renderer not implemented", format)
	default:
		return nil, fmt.Errorf("unknown format %q", format)
	}
}
