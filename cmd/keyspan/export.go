// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/alexremn/keyspan/internal/render"
	"github.com/alexremn/keyspan/internal/store"
)

var flagExportRef string

func newExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Render the blast-radius for a secret in a chosen format",
		Long: "Resolve <ref> against the current graph and render its blast-radius " +
			"in the chosen --format to --out (or stdout). Locations are redacted " +
			"unless --include-locations is set.",
		RunE: runExport,
	}
	cmd.Flags().StringVar(&flagExportRef, "ref", "",
		"secret ref: name:<n> | fp:<hash> | finding:<id> | bare (required)")
	return cmd
}

func runExport(cmd *cobra.Command, _ []string) error {
	if flagExportRef == "" {
		return fmt.Errorf("%w: --ref is required (name:<n> | fp:<hash> | finding:<id>)", errUsage)
	}

	st, err := store.Open(flagDB)
	if err != nil {
		return err
	}
	defer st.Close()

	g, err := st.LoadGraph()
	if err != nil {
		return err
	}

	id, candidates, err := g.ResolveRef(flagExportRef)
	if err != nil {
		if len(candidates) > 1 {
			cmd.PrintErrln("multiple matches for ref:")
			for _, c := range candidates {
				cmd.PrintErrf("  %s (%s)\n", c.Name, c.Type)
			}
			return fmt.Errorf("%w: %q matched %d nodes", errMultiMatch, flagExportRef, len(candidates))
		}
		return fmt.Errorf("%w: %q", errNoMatch, flagExportRef)
	}

	result := g.BlastRadius(id, flagMinConfidence)

	r, err := render.New(flagFormat)
	if err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}

	w, closeFn, err := exportWriter(cmd, flagOut)
	if err != nil {
		return err
	}
	defer closeFn()

	opts := render.Options{
		IncludeLocations: flagIncludeLocations,
		Color:            false, // file/pipe output is never colorized
	}
	return r.Render(w, result, opts)
}

// exportWriter returns the destination writer. When --out is empty, writes to
// the command's stdout; otherwise creates the file with 0600 (reports are
// sensitive, §10).
func exportWriter(cmd *cobra.Command, out string) (io.Writer, func(), error) {
	if out == "" {
		return cmd.OutOrStdout(), func() {}, nil
	}
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, func() {}, err
	}
	return f, func() { _ = f.Close() }, nil
}

// Exit codes are mapped by exitCodeFor (root.go) via the shared errNoMatch/
// errMultiMatch/errUsage sentinels; export.go returns those, not bespoke types.
