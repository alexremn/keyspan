// cmd/keyspan/version_test.go
package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestMainVersionDefaultDev(t *testing.T) {
	buf := &bytes.Buffer{}
	root := newRootCmd()
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"version"})

	if err := root.Execute(); err != nil {
		t.Fatalf("execute version: %v", err)
	}

	got := strings.TrimSpace(buf.String())
	if got != "keyspan dev" {
		t.Fatalf("default version output = %q, want %q", got, "keyspan dev")
	}
}

func TestMainVersionRespectsVersionVar(t *testing.T) {
	prev := version
	version = "1.2.3"
	t.Cleanup(func() { version = prev })

	buf := &bytes.Buffer{}
	root := newRootCmd()
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"version"})

	if err := root.Execute(); err != nil {
		t.Fatalf("execute version: %v", err)
	}

	got := strings.TrimSpace(buf.String())
	if got != "keyspan 1.2.3" {
		t.Fatalf("version output = %q, want %q", got, "keyspan 1.2.3")
	}
}

func TestMainRootDefaultFlagValues(t *testing.T) {
	_ = newRootCmd()
	if flagDB != "./keyspan.db" {
		t.Errorf("flagDB default = %q, want %q", flagDB, "./keyspan.db")
	}
	if flagMinConfidence != 0.50 {
		t.Errorf("flagMinConfidence default = %v, want 0.50", flagMinConfidence)
	}
	if flagFormat != "human" {
		t.Errorf("flagFormat default = %q, want %q", flagFormat, "human")
	}
}
