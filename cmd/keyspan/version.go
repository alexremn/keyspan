// SPDX-License-Identifier: Apache-2.0

// cmd/keyspan/version.go
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newVersionCmd prints the keyspan binary version.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the keyspan version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "keyspan %s\n", version)
			return nil
		},
	}
}
