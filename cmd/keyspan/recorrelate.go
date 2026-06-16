// SPDX-License-Identifier: Apache-2.0

// cmd/keyspan/recorrelate.go
package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/alexremn/keyspan/internal/correlate"
	"github.com/alexremn/keyspan/internal/store"
)

// newRecorrelateCmd recomputes correlates edges over the current stored graph
// and replaces them in place (e.g. after tuning rules or toggling
// --aggressive-names). It does not re-scan or re-ingest.
func newRecorrelateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "recorrelate",
		Short: "Recompute correlates edges over the current graph",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := store.Open(flagDB)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer s.Close()

			g, err := s.LoadGraph()
			if err != nil {
				return fmt.Errorf("load graph: %w", err)
			}

			runID, err := s.BeginRun("recorrelate", nil)
			if err != nil {
				return fmt.Errorf("begin run: %w", err)
			}

			edges := correlate.Correlate(g, correlate.Options{AggressiveNames: flagAggressiveNames})
			if err := s.ReplaceCorrelations(runID, edges); err != nil {
				return fmt.Errorf("replace correlations: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "recorrelated: %d correlates edges\n", len(edges))
			return nil
		},
	}
}
