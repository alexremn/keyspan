// cmd/keyspan/scan.go
package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/alexremn/keyspan/internal/correlate"
	"github.com/alexremn/keyspan/internal/scan"
	"github.com/alexremn/keyspan/internal/store"
)

func newScanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan <path...>",
		Short: "Populate the graph from GitHub Actions surfaces",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, args)
		},
	}
}

// runScan opens the store, runs every active scanner over each root, upserts the
// emitted nodes/edges under a single run, then correlates and persists edges.
// Signature is FIXED per CLI architecture.
func runScan(cmd *cobra.Command, roots []string) error {
	s, err := store.Open(flagDB)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer s.Close()

	runID, err := s.BeginRun("scan", roots)
	if err != nil {
		return fmt.Errorf("begin run: %w", err)
	}

	opts := scan.ScanOptions{Salt: s.Salt(), FingerprintInline: flagFingerprintInline}
	for _, scanner := range scan.Scanners(opts) {
		for _, root := range roots {
			nodes, edges, err := scanner.Scan(cmd.Context(), root)
			if err != nil {
				return fmt.Errorf("%s scan %q: %w", scanner.Name(), root, err)
			}
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

	fmt.Fprintf(cmd.OutOrStdout(), "scanned %d root(s); %d correlates edges\n", len(roots), len(corr))
	return nil
}
