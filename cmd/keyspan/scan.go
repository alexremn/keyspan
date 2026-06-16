// cmd/keyspan/scan.go
package main

import (
	"fmt"

	"github.com/alexremn/keyspan/internal/scan"
	"github.com/alexremn/keyspan/internal/store"

	"github.com/spf13/cobra"
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

// runScan opens the store, runs every active scanner over each root, and upserts the
// emitted nodes/edges under a single run. Signature is FIXED per CLI architecture.
func runScan(cmd *cobra.Command, roots []string) error {
	st, err := store.Open(flagDB)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	runID, err := st.BeginRun("scan", roots)
	if err != nil {
		return fmt.Errorf("begin run: %w", err)
	}

	opts := scan.ScanOptions{Salt: st.Salt(), FingerprintInline: flagFingerprintInline}
	scanners := scan.Scanners(opts)

	for _, root := range roots {
		for _, sc := range scanners {
			nodes, edges, err := sc.Scan(cmd.Context(), root)
			if err != nil {
				return fmt.Errorf("scanner %s on %s: %w", sc.Name(), root, err)
			}
			for _, n := range nodes {
				if err := st.UpsertNode(runID, n); err != nil {
					return fmt.Errorf("upsert node: %w", err)
				}
			}
			for _, e := range edges {
				if err := st.UpsertEdge(runID, e); err != nil {
					return fmt.Errorf("upsert edge: %w", err)
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "scanned %s with %s: %d nodes, %d edges\n",
				root, sc.Name(), len(nodes), len(edges))
		}
	}
	return nil
}
