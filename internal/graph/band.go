// internal/graph/band.go
// SPDX-License-Identifier: Apache-2.0

package graph

// BandOf classifies a confidence into a half-open band:
// High >= 0.85, Medium [0.60, 0.85), Low < 0.60.
func BandOf(conf float64) Band {
	switch {
	case conf >= BandHighThreshold:
		return BandHigh
	case conf >= BandMediumThreshold:
		return BandMedium
	default:
		return BandLow
	}
}
