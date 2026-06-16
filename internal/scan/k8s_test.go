package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/alexremn/keyspan/internal/graph"
)

func writeK8sFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestK8sScannerWorkloadEmitsInjectsMountsPulls(t *testing.T) {
	dir := t.TempDir()
	writeK8sFile(t, dir, "deploy.yaml", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: prod
spec:
  template:
    spec:
      imagePullSecrets:
        - name: registry-creds
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
          envFrom:
            - secretRef:
                name: bulk-secret
`)

	s := newK8sScanner(ScanOptions{})
	nodes, edges, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	byType := map[graph.EdgeType]int{}
	for _, e := range edges {
		byType[e.Type]++
	}
	if byType[graph.EdgeInjects] != 2 {
		t.Errorf("expected 2 injects edges (secretKeyRef + envFrom secretRef), got %d", byType[graph.EdgeInjects])
	}
	if byType[graph.EdgeMounts] != 1 {
		t.Errorf("expected 1 mounts edge (volume secret), got %d", byType[graph.EdgeMounts])
	}
	if byType[graph.EdgePulls] != 1 {
		t.Errorf("expected 1 pulls edge (imagePullSecret), got %d", byType[graph.EdgePulls])
	}

	// Every structural edge is confidence 1.0 and directed.
	for _, e := range edges {
		if e.Confidence != 1.0 {
			t.Errorf("edge %s confidence = %v, want 1.0", e.Type, e.Confidence)
		}
		if e.Direction != graph.Directed {
			t.Errorf("edge %s direction = %v, want directed", e.Type, e.Direction)
		}
	}

	// The consumer is the workload container; secrets are keyed by k8s secret name.
	var consumerID string
	secretNames := map[string]bool{}
	for _, n := range nodes {
		switch n.Type {
		case graph.NodeConsumer:
			consumerID = n.ID
		case graph.NodeSecret:
			secretNames[n.Name] = true
		}
	}
	for _, want := range []string{"api-secret", "bulk-secret", "tls-secret", "registry-creds"} {
		if !secretNames[want] {
			t.Errorf("missing Secret node for %q", want)
		}
	}
	// Edges originate from the consumer (Consumer → Secret per §4.5).
	for _, e := range edges {
		if e.Src != consumerID {
			t.Errorf("edge %s src = %q, want consumer %q", e.Type, e.Src, consumerID)
		}
	}
}

func TestK8sScannerDecodesAllMultiDocDocuments(t *testing.T) {
	dir := t.TempDir()
	// Three documents separated by --- in one file. A single yaml.Unmarshal would
	// drop docs 2 and 3; the streaming decoder must process all three.
	writeK8sFile(t, dir, "multidoc.yaml", `apiVersion: v1
kind: Namespace
metadata:
  name: prod
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: prod
spec:
  template:
    spec:
      containers:
        - name: app
          env:
            - name: TOKEN
              valueFrom:
                secretKeyRef:
                  name: api-secret
                  key: token
---
apiVersion: v1
kind: Secret
metadata:
  name: api-secret
  namespace: prod
data:
  token: c3VwZXJzZWNyZXR2YWx1ZQ==
`)

	s := newK8sScanner(ScanOptions{})
	nodes, _, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	// All three docs decoded: a Consumer (Deployment container), a Secret node,
	// and an Owner (namespace). If only the first doc were parsed, none of these
	// would exist.
	var consumers, secrets, owners int
	for _, n := range nodes {
		switch n.Type {
		case "consumer":
			consumers++
		case "secret":
			secrets++
		case "owner":
			owners++
		}
	}
	if consumers == 0 {
		t.Errorf("expected at least 1 consumer node from doc 2, got 0")
	}
	if secrets == 0 {
		t.Errorf("expected at least 1 secret node, got 0")
	}
	if owners == 0 {
		t.Errorf("expected at least 1 owner node from doc 1 namespace, got 0")
	}
}
