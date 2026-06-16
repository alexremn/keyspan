// SPDX-License-Identifier: Apache-2.0

// internal/graph/band_test.go
package graph

import "testing"

func TestGraphBandOfHalfOpen(t *testing.T) {
	cases := []struct {
		name string
		conf float64
		want Band
	}{
		{"exactly-high-threshold", 0.85, BandHigh},
		{"above-high", 0.95, BandHigh},
		{"one-point-zero", 1.0, BandHigh},
		{"just-below-high", 0.849, BandMedium},
		{"exactly-medium-threshold", 0.60, BandMedium},
		{"mid-medium", 0.72, BandMedium},
		{"just-below-medium", 0.599, BandLow},
		{"name-match-floor", 0.55, BandLow},
		{"zero", 0.0, BandLow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := BandOf(tc.conf); got != tc.want {
				t.Errorf("BandOf(%v) = %q, want %q", tc.conf, got, tc.want)
			}
		})
	}
}
