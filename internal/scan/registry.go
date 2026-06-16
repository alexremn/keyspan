// internal/scan/registry.go
package scan

// Scanners returns the active scanner set for a scan run. v1.0 (this phase): GHA only.
// Phase 4 appends the k8s scanner here.
func Scanners(opts ScanOptions) []Scanner {
	return []Scanner{
		newGHAScanner(),
	}
}
