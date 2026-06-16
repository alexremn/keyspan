// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/alexremn/keyspan/internal/graph"
)

// ANSI color codes; applied only when Options.Color is set.
const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiGreen  = "\x1b[32m"
)

type humanRenderer struct{}

// Render writes an indented tree: the start identity, then each consumer with
// its confidence band and a one-line provenance. Locations are omitted unless
// opts.IncludeLocations (redaction-safe default).
func (h *humanRenderer) Render(w io.Writer, r graph.QueryResult, opts Options) error {
	if _, err := fmt.Fprintf(w, "%s\n", h.color(opts, ansiBold, r.Start.Name)); err != nil {
		return err
	}
	if len(r.Cluster) > 1 {
		if _, err := fmt.Fprintf(w, "  identity cluster: %d correlated secrets\n", len(r.Cluster)); err != nil {
			return err
		}
	}
	if len(r.Consumers) == 0 {
		_, err := fmt.Fprintln(w, "  (no consumers)")
		return err
	}
	for _, c := range r.Consumers {
		if err := h.writeConsumer(w, c, opts); err != nil {
			return err
		}
	}
	return nil
}

func (h *humanRenderer) writeConsumer(w io.Writer, c graph.ConsumerHit, opts Options) error {
	band := h.color(opts, h.bandColor(c.Band), string(c.Band))
	if _, err := fmt.Fprintf(w, "  ├─ %s  [%s %.2f]\n", c.Node.Name, band, c.Confidence); err != nil {
		return err
	}
	for _, e := range c.Chain {
		line := h.provenanceLine(e, opts)
		if _, err := fmt.Fprintf(w, "  │    %s\n", line); err != nil {
			return err
		}
	}
	if len(c.Owners) > 0 {
		names := make([]string, 0, len(c.Owners))
		for _, o := range c.Owners {
			names = append(names, o.Name)
		}
		if _, err := fmt.Fprintf(w, "  │    owners: %s\n", strings.Join(names, ", ")); err != nil {
			return err
		}
	}
	return nil
}

// provenanceLine is the one-line "why": ruleID, joined evidence, and (only when
// IncludeLocations) the File:Line locations.
func (h *humanRenderer) provenanceLine(e graph.Edge, opts Options) string {
	parts := []string{string(e.Type), e.Provenance.RuleID}
	if len(e.Provenance.Evidence) > 0 {
		parts = append(parts, strings.Join(e.Provenance.Evidence, "; "))
	}
	if opts.IncludeLocations {
		for _, loc := range e.Provenance.Locations {
			parts = append(parts, fmt.Sprintf("%s:%d", loc.File, loc.Line))
		}
	}
	return strings.Join(parts, " — ")
}

func (h *humanRenderer) bandColor(b graph.Band) string {
	switch b {
	case graph.BandHigh:
		return ansiGreen
	case graph.BandMedium:
		return ansiYellow
	default:
		return ansiRed
	}
}

func (h *humanRenderer) color(opts Options, code, s string) string {
	if !opts.Color {
		return s
	}
	return code + s + ansiReset
}
