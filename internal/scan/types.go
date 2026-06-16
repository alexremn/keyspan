// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"

	"github.com/alexremn/keyspan/internal/graph"
)

// Scanner reads a surface rooted at a directory and emits graph nodes/edges.
type Scanner interface {
	Name() string
	Scan(ctx context.Context, root string) ([]graph.Node, []graph.Edge, error)
}

// Ingester reads a single detection report file and emits graph nodes/edges.
type Ingester interface {
	Name() string
	Ingest(ctx context.Context, reportPath string) ([]graph.Node, []graph.Edge, error)
}

// ScanOptions configures a scan run. Salt is the per-DB HMAC salt used for
// fingerprints; FingerprintInline hashes inline k8s Secret values (then discards
// them) so they can correlate with findings — off by default (§5.3).
type ScanOptions struct {
	FingerprintInline bool
	Salt              []byte
}
