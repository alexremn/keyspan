// cmd/keyspan/main.go
// SPDX-License-Identifier: Apache-2.0

// Command keyspan is a secret blast-radius graph CLI.
package main

import (
	"fmt"
	"os"
)

// version is overridden at build time via -ldflags.
var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "keyspan:", err)
		return exitCodeFor(err)
	}
	return exitOK
}
