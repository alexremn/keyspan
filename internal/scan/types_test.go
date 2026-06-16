// SPDX-License-Identifier: Apache-2.0

// internal/scan/types_test.go
package scan

import "testing"

func TestScanOptionsZeroValue(t *testing.T) {
	var o ScanOptions
	if o.FingerprintInline {
		t.Fatalf("FingerprintInline should default to false")
	}
	if o.Salt != nil {
		t.Fatalf("Salt should default to nil, got %v", o.Salt)
	}
}
