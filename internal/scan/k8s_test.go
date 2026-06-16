package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexremn/keyspan/internal/graph"
	"github.com/alexremn/keyspan/internal/normalize"
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

func TestK8sScannerExternalSecretSyncsPivotAndStoreKey(t *testing.T) {
	dir := t.TempDir()
	writeK8sFile(t, dir, "es.yaml", `apiVersion: external-secrets.io/v1beta1
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
`)

	s := newK8sScanner(ScanOptions{})
	nodes, edges, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	// Exactly one syncs edge: ExternalSecret Consumer → materialized k8s Secret.
	var syncs []graph.Edge
	for _, e := range edges {
		if e.Type == graph.EdgeSyncs {
			syncs = append(syncs, e)
		}
	}
	if len(syncs) != 1 {
		t.Fatalf("expected 1 syncs edge, got %d", len(syncs))
	}
	if syncs[0].Direction != graph.Directed || syncs[0].Confidence != 1.0 {
		t.Errorf("syncs edge direction/conf = %v/%v, want directed/1.0", syncs[0].Direction, syncs[0].Confidence)
	}

	// The pivot Secret node is keyed by the target k8s secret name (api-secret),
	// matching what a workload's injects edge would point at (§6 reference-chain).
	_, pivotID := secretNodeByName("api-secret")
	if syncs[0].Dst != pivotID {
		t.Errorf("syncs dst = %q, want pivot api-secret %q", syncs[0].Dst, pivotID)
	}

	// A store-keyed Secret node (store:<remoteRef.key>) exists for v1.1 backend
	// attachment, and the ExternalSecret consumer carries the remoteRef key attr.
	_, storeID := secretNodeByStoreKey("prod/api/token")
	var foundStore, foundConsumerAttr bool
	for _, n := range nodes {
		if n.ID == storeID && n.Type == graph.NodeSecret {
			foundStore = true
		}
		if n.Type == graph.NodeConsumer && n.Attrs["remote_ref_keys"] == "prod/api/token" {
			foundConsumerAttr = true
		}
	}
	if !foundStore {
		t.Errorf("missing store-keyed Secret node for remoteRef key prod/api/token")
	}
	if !foundConsumerAttr {
		t.Errorf("ExternalSecret consumer missing remote_ref_keys attr")
	}
}

func TestK8sScannerNamespaceOwnedByEdge(t *testing.T) {
	dir := t.TempDir()
	writeK8sFile(t, dir, "ns-and-deploy.yaml", `apiVersion: v1
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
`)

	s := newK8sScanner(ScanOptions{})
	nodes, edges, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	ownerID := graph.NodeID(graph.NodeOwner, "ns:prod")
	var ownerNode bool
	for _, n := range nodes {
		if n.ID == ownerID && n.Type == graph.NodeOwner {
			ownerNode = true
		}
	}
	if !ownerNode {
		t.Fatalf("missing namespace Owner node ns:prod")
	}

	// The Deployment consumer owned_by the prod namespace Owner (directed conf 1.0).
	var found bool
	for _, e := range edges {
		if e.Type != graph.EdgeOwnedBy {
			continue
		}
		if e.Dst == ownerID && e.Direction == graph.Directed && e.Confidence == 1.0 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected owned_by edge to ns:prod owner, got none")
	}
}

func TestK8sScannerFingerprintInlineHashesAndNeverPersistsRaw(t *testing.T) {
	dir := t.TempDir()
	// data.token base64-decodes to the raw value "supersecretvalue".
	const rawValue = "supersecretvalue"
	writeK8sFile(t, dir, "secret.yaml", `apiVersion: v1
kind: Secret
metadata:
  name: api-secret
  namespace: prod
data:
  token: c3VwZXJzZWNyZXR2YWx1ZQ==
stringData:
  plain: supersecretvalue
`)

	salt := []byte("0123456789abcdef0123456789abcdef")

	// Mode OFF (default): no fingerprint computed; only the key name is recorded.
	off := newK8sScanner(ScanOptions{FingerprintInline: false, Salt: salt})
	offNodes, _, err := off.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("off-mode scan error: %v", err)
	}
	for _, n := range offNodes {
		if n.Type == graph.NodeSecret && n.Fingerprint != "" {
			t.Errorf("FingerprintInline off: secret %q must have no fingerprint, got %q", n.Name, n.Fingerprint)
		}
	}

	// Mode ON: a fingerprint is computed from the decoded value; raw never appears.
	on := newK8sScanner(ScanOptions{FingerprintInline: true, Salt: salt})
	onNodes, _, err := on.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("on-mode scan error: %v", err)
	}
	var fingerprinted bool
	want := normalize.Fingerprint(salt, rawValue)
	for _, n := range onNodes {
		if n.Type != graph.NodeSecret {
			continue
		}
		if n.Fingerprint == want {
			fingerprinted = true
		}
		// Raw value must never land in any persisted field.
		if strings.Contains(n.Name, rawValue) || strings.Contains(n.Fingerprint, rawValue) {
			t.Errorf("raw value leaked in node %q (name=%q fp=%q)", n.ID, n.Name, n.Fingerprint)
		}
		for k, v := range n.Attrs {
			if strings.Contains(v, rawValue) {
				t.Errorf("raw value leaked in attr %s=%q", k, v)
			}
		}
	}
	if !fingerprinted {
		t.Errorf("FingerprintInline on: expected a secret fingerprinted to %q", want)
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
