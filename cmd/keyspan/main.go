// cmd/keyspan/main.go
// SPDX-License-Identifier: Apache-2.0

// Command keyspan is a secret blast-radius graph CLI.
package main

import "os"

// version is overridden at build time via -ldflags.
var version = "dev"

func main() {
	os.Exit(run())
}

// run builds the root command and executes it. In Phase 1 only the version
// command exists, so any error maps to exitRuntime; Phase 2 rewrites run() to
// map the shared exit-code sentinels via exitCodeFor (blastradius.go).
func run() int {
	if err := newRootCmd().Execute(); err != nil {
		return exitRuntime
	}
	return exitOK
}
