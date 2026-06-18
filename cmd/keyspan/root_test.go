// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"testing"
)

// TestUsageErrorsExitTwo asserts that cobra-level usage mistakes (missing
// required positional arg, unknown flag, unknown subcommand) are all mapped to
// exit code 2 by exitCodeFor, matching the §9 contract.
func TestUsageErrorsExitTwo(t *testing.T) {
	t.Cleanup(func() { flagDB = "./keyspan.db" })

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "missing required arg for scan",
			args: []string{"scan"},
		},
		{
			name: "missing required arg for blast-radius",
			args: []string{"blast-radius"},
		},
		{
			name: "missing required arg for ingest",
			args: []string{"ingest"},
		},
		{
			name: "unknown flag",
			args: []string{"--no-such-flag"},
		},
		{
			name: "unknown subcommand",
			args: []string{"no-such-subcommand"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(func() { flagDB = "./keyspan.db" })

			root := newRootCmd()
			root.SetOut(&bytes.Buffer{})
			root.SetErr(&bytes.Buffer{})
			root.SetArgs(tc.args)

			err := executeRoot(root)
			if err == nil {
				t.Fatalf("expected error for args %v, got nil", tc.args)
			}
			if got := exitCodeFor(err); got != exitUsage {
				t.Fatalf("exitCodeFor(%q) = %d, want %d (exitUsage); err = %v",
					tc.name, got, exitUsage, err)
			}
		})
	}
}
