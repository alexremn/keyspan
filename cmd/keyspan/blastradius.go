// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/alexremn/keyspan/internal/graph"
	"github.com/alexremn/keyspan/internal/render"
	"github.com/alexremn/keyspan/internal/store"
)

// errNoMatch, errMultiMatch, and errUsage are the shared exit-code sentinels
// (§9): no-match → 3, multi-match/usage → 2. Every subcommand wraps these with
// fmt.Errorf("...: %w", errX); exitCodeFor centralizes the mapping (also used in
// tests and by the export command).
var (
	errNoMatch    = errors.New("no matching node")
	errMultiMatch = errors.New("multiple matching nodes")
	errUsage      = errors.New("usage error")
)

func exitCodeFor(err error) int {
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, errNoMatch):
		return exitNoMatch
	case errors.Is(err, errMultiMatch):
		return exitUsage
	case errors.Is(err, errUsage):
		return exitUsage
	default:
		return exitRuntime
	}
}

func newBlastRadiusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "blast-radius <ref>",
		Short: "Show what breaks if you rotate a credential, and who owns it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref := args[0]

			st, err := store.Open(flagDB)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()

			g, err := st.LoadGraph()
			if err != nil {
				return fmt.Errorf("load graph: %w", err)
			}

			startID, candidates, err := g.ResolveRef(ref)
			if err != nil {
				if len(candidates) > 1 {
					listCandidates(cmd, candidates)
					return fmt.Errorf("%w: %q matched %d nodes", errMultiMatch, ref, len(candidates))
				}
				return fmt.Errorf("%w: %q", errNoMatch, ref)
			}

			result := g.BlastRadius(startID, flagMinConfidence)

			renderer, err := render.New(flagFormat)
			if err != nil {
				return err
			}
			w, closeFn, err := outputWriter(cmd)
			if err != nil {
				return err
			}
			defer closeFn()

			opts := render.Options{
				IncludeLocations: flagIncludeLocations,
				Color:            isTTY(os.Stdout),
			}
			return renderer.Render(w, result, opts)
		},
	}
	return cmd
}

func listCandidates(cmd *cobra.Command, candidates []graph.Node) {
	out := cmd.OutOrStdout()
	fmt.Fprintln(out, "ambiguous ref; candidates:")
	for _, n := range candidates {
		fmt.Fprintf(out, "  %s  (%s) %s\n", n.ID, n.Type, n.Name)
	}
}

// outputWriter returns the target for rendered output: a file when --out is set,
// otherwise the command's stdout. The returned closeFn is always safe to call.
func outputWriter(cmd *cobra.Command) (w interface {
	Write([]byte) (int, error)
}, closeFn func(), err error) {
	if strings.TrimSpace(flagOut) == "" {
		return cmd.OutOrStdout(), func() {}, nil
	}
	f, err := os.OpenFile(flagOut, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open --out file: %w", err)
	}
	return f, func() { _ = f.Close() }, nil
}
