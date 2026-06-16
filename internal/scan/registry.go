// SPDX-License-Identifier: Apache-2.0

// internal/scan/registry.go
package scan

// Scanners returns the registered surface scanners. New surface = one new
// scanner appended here, zero core changes elsewhere.
func Scanners(opts ScanOptions) []Scanner {
	return []Scanner{
		newGHAScanner(),
		newK8sScanner(opts),
	}
}
