// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/alexremn/keyspan/internal/correlate"
	"github.com/alexremn/keyspan/internal/graph"
	"github.com/alexremn/keyspan/internal/scan"
	"github.com/alexremn/keyspan/internal/store"
)

func newIngestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ingest <tool> <report>",
		Short: "Ingest a secret-detection report (gitleaks|trufflehog) as graph entry points",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			tool, reportPath := args[0], args[1]

			st, err := store.Open(flagDB)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()

			var ing scan.Ingester
			switch tool {
			case "gitleaks":
				ing = scan.NewGitleaksIngester(st.Salt())
			case "trufflehog":
				ing = scan.NewTrufflehogIngester(st.Salt())
			default:
				return fmt.Errorf("%w: unknown ingest tool %q (want gitleaks|trufflehog)", errUsage, tool)
			}

			nodes, edges, err := ing.Ingest(cmd.Context(), reportPath)
			if err != nil {
				return fmt.Errorf("ingest %s: %w", tool, err)
			}
			runID, err := st.BeginRun("ingest "+tool, []string{reportPath})
			if err != nil {
				return fmt.Errorf("begin run: %w", err)
			}
			return finishIngest(cmd, st, runID, tool, nodes, edges)
		},
	}
	return cmd
}

// finishIngest persists ingester output and recomputes correlations so a later
// blast-radius reads a fully-correlated graph without re-running anything.
func finishIngest(cmd *cobra.Command, s *store.Store, runID int64, source string, nodes []graph.Node, edges []graph.Edge) error {
	for _, n := range nodes {
		if err := s.UpsertNode(runID, n); err != nil {
			return fmt.Errorf("upsert node: %w", err)
		}
	}
	for _, e := range edges {
		if err := s.UpsertEdge(runID, e); err != nil {
			return fmt.Errorf("upsert edge: %w", err)
		}
	}

	g, err := s.LoadGraph()
	if err != nil {
		return fmt.Errorf("load graph: %w", err)
	}
	corr := correlate.Correlate(g, correlate.Options{AggressiveNames: flagAggressiveNames})
	if err := s.ReplaceCorrelations(runID, corr); err != nil {
		return fmt.Errorf("replace correlations: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "ingested %s: %d node(s), %d edge(s); %d correlates edges\n", source, len(nodes), len(edges), len(corr))
	return nil
}
