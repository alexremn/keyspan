// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

// Exit codes (see design spec §9).
const (
	exitOK      = 0
	exitRuntime = 1
	exitUsage   = 2
	exitNoMatch = 3
)

// Package-level global flag vars, bound on PersistentFlags in newRootCmd.
// Defaults are set here so tests that pre-set a var before calling newRootCmd()
// retain their value (pflag uses the current value as the flag default).
var (
	flagDB                = "./keyspan.db"
	flagMinConfidence     = 0.50
	flagFormat            = "human"
	flagOut               = ""
	flagIncludeLocations  = false
	flagAggressiveNames   = false
	flagFingerprintInline = false
)

// wrapArgsUsage wraps a cobra positional-arguments validator so that any
// validation failure carries errUsage, mapping it to exit code 2 (§9).
func wrapArgsUsage(v cobra.PositionalArgs) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := v(cmd, args); err != nil {
			return fmt.Errorf("%w: %v", errUsage, err)
		}
		return nil
	}
}

// newRootCmd builds the keyspan root command and registers subcommands.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "keyspan",
		Short:         "Secret blast-radius graph",
		Long:          "keyspan reads repos, CI configs, and k8s/ESO manifests, ingests secret-detection findings, and answers: if I rotate this credential, what breaks and who owns it?",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Wrap cobra's flag-parse errors with errUsage so exitCodeFor maps them
	// to exit 2 rather than the default exit 1.
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return fmt.Errorf("%w: %v", errUsage, err)
	})

	pf := root.PersistentFlags()
	pf.StringVar(&flagDB, "db", flagDB, "path to the keyspan SQLite DB")
	pf.Float64Var(&flagMinConfidence, "min-confidence", flagMinConfidence, "minimum edge confidence (inclusive)")
	pf.StringVar(&flagFormat, "format", flagFormat, "output format: human|json|dot|html")
	pf.StringVar(&flagOut, "out", flagOut, "write output to FILE instead of stdout")
	pf.BoolVar(&flagIncludeLocations, "include-locations", flagIncludeLocations, "include File:Line locations in output")
	pf.BoolVar(&flagAggressiveNames, "aggressive-names", flagAggressiveNames, "strip enumerated name prefixes/suffixes in name-match")
	pf.BoolVar(&flagFingerprintInline, "fingerprint-inline", flagFingerprintInline, "hash inline k8s Secret values for correlation")

	root.AddCommand(newVersionCmd())
	root.AddCommand(newIngestCmd())
	root.AddCommand(newBlastRadiusCmd())
	root.AddCommand(newScanCmd())
	root.AddCommand(newRecorrelateCmd())
	root.AddCommand(newExportCmd())

	return root
}

// executeRoot runs cmd.Execute() and normalises cobra's "unknown command" errors
// (which cobra returns as plain strings) to carry errUsage, so exitCodeFor maps
// them to exit code 2 per §9.  Both run() and tests must call this instead of
// Execute() directly so the exit-code contract is consistently enforced.
func executeRoot(root *cobra.Command) error {
	err := root.Execute()
	if err == nil {
		return nil
	}
	// Cobra reports unknown subcommands as a plain error string; there is no
	// structured sentinel, so we inspect the prefix.
	if strings.HasPrefix(err.Error(), "unknown command") {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	return err
}

// isTTY reports whether f is an interactive terminal.
func isTTY(f *os.File) bool {
	return isatty.IsTerminal(f.Fd())
}
