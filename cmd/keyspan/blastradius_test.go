package main

import (
	"bytes"
	"path/filepath"
	"testing"
)

// seedGitleaksDB ingests the basic gitleaks fixture into a fresh DB and returns
// its path, so blast-radius has a finding consumer to surface.
func seedGitleaksDB(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keyspan.db")
	root := newRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{
		"--db", dbPath,
		"ingest", "gitleaks",
		"../../internal/scan/testdata/gitleaks/basic.json",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("seed ingest: %v", err)
	}
	return dbPath
}

func TestCmdBlastRadiusShowsFindingConsumer(t *testing.T) {
	// Arrange: the basic gitleaks fixture names the secret after its rule.
	dbPath := seedGitleaksDB(t)
	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{
		"--db", dbPath,
		"blast-radius", "name:aws-access-token",
	})

	// Act
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// Assert: the human tree surfaces the finding (detected_as consumer).
	out := buf.String()
	if !bytes.Contains([]byte(out), []byte("aws-access-token")) {
		t.Fatalf("expected blast-radius to show the secret/finding, got:\n%s", out)
	}
}

func TestCmdBlastRadiusNoMatchExitsThree(t *testing.T) {
	// Arrange
	dbPath := seedGitleaksDB(t)
	root := newRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SilenceErrors = true
	root.SetArgs([]string{
		"--db", dbPath,
		"blast-radius", "name:does-not-exist",
	})

	// Act
	err := root.Execute()

	// Assert: a no-match is a distinct, typed error mapped to exit 3 by run().
	if err == nil {
		t.Fatalf("expected no-match error, got nil")
	}
	if ec := exitCodeFor(err); ec != exitNoMatch {
		t.Fatalf("exit code for no-match = %d, want %d", ec, exitNoMatch)
	}
}
