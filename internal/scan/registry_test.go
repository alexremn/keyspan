// internal/scan/registry_test.go
package scan

import (
	"context"
	"testing"

	"github.com/alexremn/keyspan/internal/graph"
)

func TestRegistryScannersReturnsGHA(t *testing.T) {
	// Arrange
	opts := ScanOptions{FingerprintInline: false, Salt: []byte("test-salt")}

	// Act
	scanners := Scanners(opts)

	// Assert
	if len(scanners) != 1 {
		t.Fatalf("len(Scanners) = %d, want 1", len(scanners))
	}
	if scanners[0].Name() != "gha" {
		t.Fatalf("Scanners()[0].Name() = %q, want %q", scanners[0].Name(), "gha")
	}
}

func TestRegistryGHAScannerEmitsWorkflowsAndOwners(t *testing.T) {
	// Arrange
	opts := ScanOptions{Salt: []byte("test-salt")}
	s := Scanners(opts)[0]

	// Act
	nodes, edges, err := s.Scan(context.Background(), "testdata/gha/repo")
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	// Assert: at least one references edge (from workflows) AND one owned_by edge (from CODEOWNERS).
	var refs, owns int
	for _, e := range edges {
		switch e.Type {
		case graph.EdgeReferences:
			refs++
		case graph.EdgeOwnedBy:
			owns++
		}
	}
	if refs == 0 {
		t.Fatalf("expected references edges from workflows, got 0")
	}
	if owns == 0 {
		t.Fatalf("expected owned_by edges from CODEOWNERS, got 0")
	}
	if len(nodes) == 0 {
		t.Fatalf("expected nodes, got 0")
	}
}
