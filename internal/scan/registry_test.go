// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/alexremn/keyspan/internal/graph"
)

func TestRegistryScannersIncludesGhaAndK8s(t *testing.T) {
	scanners := Scanners(ScanOptions{})

	names := map[string]bool{}
	for _, sc := range scanners {
		names[sc.Name()] = true
	}
	if !names["gha"] {
		t.Errorf("Scanners missing gha scanner; got %v", names)
	}
	if !names["k8s"] {
		t.Errorf("Scanners missing k8s scanner; got %v", names)
	}
}

func TestRegistryScannersOverMixedFixtureProducesAllStructuralEdges(t *testing.T) {
	dir := t.TempDir()

	// A GHA workflow (gha scanner) ...
	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(`name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: deploy
        env:
          TOKEN: ${{ secrets.API_SECRET }}
`), 0o600); err != nil {
		t.Fatal(err)
	}

	// ... plus k8s manifests exercising injects, mounts, and syncs.
	if err := os.WriteFile(filepath.Join(dir, "manifests.yaml"), []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: prod
spec:
  template:
    spec:
      volumes:
        - name: vol
          secret:
            secretName: tls-secret
      containers:
        - name: app
          env:
            - name: TOKEN
              valueFrom:
                secretKeyRef:
                  name: api-secret
                  key: token
---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: api-external
  namespace: prod
spec:
  target:
    name: api-secret
  data:
    - secretKey: token
      remoteRef:
        key: prod/api/token
`), 0o600); err != nil {
		t.Fatal(err)
	}

	byType := map[graph.EdgeType]int{}
	for _, sc := range Scanners(ScanOptions{}) {
		_, edges, err := sc.Scan(context.Background(), dir)
		if err != nil {
			t.Fatalf("scanner %s error: %v", sc.Name(), err)
		}
		for _, e := range edges {
			byType[e.Type]++
		}
	}

	if byType[graph.EdgeInjects] == 0 {
		t.Errorf("expected injects edges from k8s workload, got 0")
	}
	if byType[graph.EdgeMounts] == 0 {
		t.Errorf("expected mounts edges from k8s volume secret, got 0")
	}
	if byType[graph.EdgeSyncs] == 0 {
		t.Errorf("expected syncs edges from ExternalSecret, got 0")
	}
}
