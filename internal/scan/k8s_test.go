package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeK8sFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
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
