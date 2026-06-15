// cmd/keyspan/root.go
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

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
var (
	flagDB               string
	flagMinConfidence    float64
	flagFormat           string
	flagOut              string
	flagIncludeLocations bool
	flagAggressiveNames  bool
	flagFingerprintInline bool
)

// newRootCmd builds the keyspan root command and registers subcommands.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "keyspan",
		Short:         "Secret blast-radius graph",
		Long:          "keyspan reads repos, CI configs, and k8s/ESO manifests, ingests secret-detection findings, and answers: if I rotate this credential, what breaks and who owns it?",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	pf := root.PersistentFlags()
	pf.StringVar(&flagDB, "db", "./keyspan.db", "path to the keyspan SQLite DB")
	pf.Float64Var(&flagMinConfidence, "min-confidence", 0.50, "minimum edge confidence (inclusive)")
	pf.StringVar(&flagFormat, "format", "human", "output format: human|json|dot|html")
	pf.StringVar(&flagOut, "out", "", "write output to FILE instead of stdout")
	pf.BoolVar(&flagIncludeLocations, "include-locations", false, "include File:Line locations in output")
	pf.BoolVar(&flagAggressiveNames, "aggressive-names", false, "strip enumerated name prefixes/suffixes in name-match")
	pf.BoolVar(&flagFingerprintInline, "fingerprint-inline", false, "hash inline k8s Secret values for correlation")

	root.AddCommand(newVersionCmd())
	root.AddCommand(newIngestCmd())
	root.AddCommand(newBlastRadiusCmd())

	return root
}

// isTTY reports whether f is an interactive terminal.
func isTTY(f *os.File) bool {
	return isatty.IsTerminal(f.Fd())
}
