// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/spf13/cobra"

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
				return fmt.Errorf("unknown ingest tool %q (want gitleaks|trufflehog)", tool)
			}

			if err := scan.PersistIngest(cmd.Context(), st, ing, reportPath); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "ingested %s report %s into %s\n", tool, reportPath, flagDB)
			return nil
		},
	}
	return cmd
}
