// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"fmt"

	"github.com/alexremn/keyspan/internal/store"
)

// PersistIngest runs an Ingester against a report and writes the resulting
// nodes/edges into the store under a fresh run. Structural-only: it does NOT
// compute correlates edges (the correlator does that in a later phase).
func PersistIngest(ctx context.Context, st *store.Store, ing Ingester, reportPath string) error {
	nodes, edges, err := ing.Ingest(ctx, reportPath)
	if err != nil {
		return fmt.Errorf("ingest %s: %w", ing.Name(), err)
	}
	runID, err := st.BeginRun("ingest "+ing.Name(), []string{reportPath})
	if err != nil {
		return fmt.Errorf("begin run: %w", err)
	}
	for _, n := range nodes {
		if err := st.UpsertNode(runID, n); err != nil {
			return fmt.Errorf("upsert node %s: %w", n.ID, err)
		}
	}
	for _, e := range edges {
		if err := st.UpsertEdge(runID, e); err != nil {
			return fmt.Errorf("upsert edge %s: %w", e.ID, err)
		}
	}
	return nil
}
