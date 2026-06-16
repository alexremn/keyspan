// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestCmdIngestGitleaksPopulatesDB(t *testing.T) {
	// Arrange
	t.Cleanup(func() { flagDB = "./keyspan.db" }) // restore global after --db flag mutates it
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyspan.db")
	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{
		"--db", dbPath,
		"ingest", "gitleaks",
		"../../internal/scan/testdata/gitleaks/basic.json",
	})

	// Act
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// Assert: command reports what it ingested
	out := buf.String()
	if !bytes.Contains([]byte(out), []byte("gitleaks")) {
		t.Fatalf("expected output to mention gitleaks, got %q", out)
	}
}

func TestCmdIngestUnknownToolUsageError(t *testing.T) {
	// Arrange
	t.Cleanup(func() { flagDB = "./keyspan.db" }) // restore global after --db flag mutates it
	dir := t.TempDir()
	root := newRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{
		"--db", filepath.Join(dir, "keyspan.db"),
		"ingest", "nope", "x.json",
	})

	// Act
	err := root.Execute()

	// Assert
	if err == nil {
		t.Fatalf("expected error for unknown tool, got nil")
	}
}
