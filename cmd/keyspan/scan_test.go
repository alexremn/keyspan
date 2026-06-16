// SPDX-License-Identifier: Apache-2.0

// cmd/keyspan/scan_test.go
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexremn/keyspan/internal/store"
)

// writeScanFixtureRepo creates a tiny repo with one workflow that references a secret.
func writeScanFixtureRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	wfDir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	wf := "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - name: deploy\n        run: deploy.sh\n        with:\n          token: ${{ secrets.DEPLOY_TOKEN }}\n"
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(wf), 0o600); err != nil {
		t.Fatalf("write workflow: %v", err)
	}
	co := "*  @org/platform\n"
	if err := os.WriteFile(filepath.Join(root, ".github", "CODEOWNERS"), []byte(co), 0o600); err != nil {
		t.Fatalf("write codeowners: %v", err)
	}
	return root
}

func TestScanCommandPopulatesGraph(t *testing.T) {
	// Arrange
	repo := writeScanFixtureRepo(t)
	dbPath := filepath.Join(t.TempDir(), "keyspan.db")
	t.Cleanup(func() { flagDB = "./keyspan.db" }) // restore global after --db flag mutates it

	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"--db", dbPath, "scan", repo})

	// Act
	if err := root.Execute(); err != nil {
		t.Fatalf("scan command error = %v (output: %s)", err, buf.String())
	}

	// Assert: the graph persisted to the DB has a Consumer and a Secret node.
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	g, err := st.LoadGraph()
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	var consumers, secrets int
	for _, n := range g.Nodes() {
		switch n.Type {
		case "consumer":
			consumers++
		case "secret":
			secrets++
		}
	}
	if consumers == 0 {
		t.Fatalf("expected consumer nodes in DB, got 0")
	}
	if secrets == 0 {
		t.Fatalf("expected secret nodes in DB, got 0")
	}
}

func TestScanCommandRequiresPath(t *testing.T) {
	// Arrange
	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"scan"})

	// Act
	err := root.Execute()

	// Assert: cobra Args validation rejects a missing path.
	if err == nil {
		t.Fatalf("expected error when no path given")
	}
	if !strings.Contains(err.Error(), "arg") {
		t.Fatalf("error = %q, want it to mention args", err.Error())
	}
}
