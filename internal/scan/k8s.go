// SPDX-License-Identifier: Apache-2.0

// internal/scan/k8s.go
package scan

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/alexremn/keyspan/internal/graph"
	"github.com/alexremn/keyspan/internal/normalize"
)

// workloadKinds are the pod-spec-bearing kinds whose containers we scan.
var workloadKinds = map[string]bool{
	"Deployment":  true,
	"StatefulSet": true,
	"DaemonSet":   true,
	"CronJob":     true,
	"Job":         true,
	"Pod":         true,
}

// k8sScanner walks a root for *.yaml/*.yml manifests, streaming-decodes every
// document (multi-doc safe), and emits Consumer/Secret/Owner nodes plus
// injects/mounts/pulls/syncs/owned_by edges. It reads KEY NAMES ONLY and never
// decodes secret data:/stringData: values unless FingerprintInline is set.
type k8sScanner struct {
	opts ScanOptions
}

func newK8sScanner(opts ScanOptions) *k8sScanner {
	return &k8sScanner{opts: opts}
}

func (s *k8sScanner) Name() string { return "k8s" }

func (s *k8sScanner) Scan(ctx context.Context, root string) ([]graph.Node, []graph.Edge, error) {
	var nodes []graph.Node
	var edges []graph.Edge

	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			return nil
		}
		if !isYAMLPath(path) {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		fileNodes, fileEdges, scanErr := s.scanFile(path, rel)
		if scanErr != nil {
			return fmt.Errorf("scan %s: %w", rel, scanErr)
		}
		nodes = append(nodes, fileNodes...)
		edges = append(edges, fileEdges...)
		return nil
	})
	if walkErr != nil {
		return nil, nil, walkErr
	}
	return nodes, edges, nil
}

// isYAMLPath reports whether path has a YAML extension. Named distinctly from
// gha.go's isYAMLFile to avoid a package-level redeclaration in package scan.
func isYAMLPath(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}

// scanFile streaming-decodes every YAML document in a single file. yaml.v3's
// Decoder.Decode loop is mandatory: a single Unmarshal silently drops every
// document after the first `---`.
func (s *k8sScanner) scanFile(path, rel string) ([]graph.Node, []graph.Edge, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	var nodes []graph.Node
	var edges []graph.Edge
	dec := yaml.NewDecoder(f)
	for {
		var doc map[string]any
		decErr := dec.Decode(&doc)
		if errors.Is(decErr, io.EOF) {
			break
		}
		if decErr != nil {
			return nil, nil, fmt.Errorf("decode document: %w", decErr)
		}
		if doc == nil {
			continue
		}
		dn, de := s.dispatch(doc, rel)
		nodes = append(nodes, dn...)
		edges = append(edges, de...)
	}
	return nodes, edges, nil
}

// dispatch routes a single decoded manifest by its kind.
func (s *k8sScanner) dispatch(doc map[string]any, rel string) ([]graph.Node, []graph.Edge) {
	kind, _ := doc["kind"].(string)
	switch {
	case workloadKinds[kind]:
		return s.scanWorkload(doc, kind, rel)
	case kind == "Secret":
		return s.scanSecret(doc, rel)
	case kind == "ExternalSecret":
		return s.scanExternalSecret(doc, rel)
	case kind == "Namespace":
		return s.scanNamespace(doc)
	default:
		return nil, nil
	}
}

func (s *k8sScanner) scanWorkload(doc map[string]any, kind, rel string) ([]graph.Node, []graph.Edge) {
	ns := metaNamespace(doc)
	name := metaName(doc)
	spec := podSpec(doc, kind)
	if spec == nil {
		return nil, nil
	}
	containers := podContainers(doc, kind)
	if len(containers) == 0 {
		return nil, nil
	}

	loc := graph.Location{File: rel, Surface: "k8s"}
	var nodes []graph.Node
	var edges []graph.Edge

	// Pod-level secret references (imagePullSecrets, volumes) attach to the first
	// container so they always have a valid Consumer source.
	firstConsumerID := ""

	for i, c := range containers {
		cName, _ := c["name"].(string)
		consumer := s.consumerNode(ns, kind, name, cName)
		nodes = append(nodes, consumer)
		if i == 0 {
			firstConsumerID = consumer.ID
		}

		// env[].valueFrom.secretKeyRef → injects
		for _, secretName := range envSecretKeyRefs(c) {
			sn, edge := s.secretEdge(consumer.ID, secretName, graph.EdgeInjects, "secretKeyRef", loc)
			nodes = append(nodes, sn)
			edges = append(edges, edge)
		}
		// envFrom[].secretRef → injects
		for _, secretName := range envFromSecretRefs(c) {
			sn, edge := s.secretEdge(consumer.ID, secretName, graph.EdgeInjects, "envFrom.secretRef", loc)
			nodes = append(nodes, sn)
			edges = append(edges, edge)
		}
	}

	// volumes[].secret.secretName → mounts (pod-level)
	for _, secretName := range volumeSecrets(spec) {
		sn, edge := s.secretEdge(firstConsumerID, secretName, graph.EdgeMounts, "volume.secret", loc)
		nodes = append(nodes, sn)
		edges = append(edges, edge)
	}
	// imagePullSecrets[].name → pulls (pod-level, lower signal)
	for _, secretName := range imagePullSecrets(spec) {
		sn, edge := s.secretEdge(firstConsumerID, secretName, graph.EdgePulls, "imagePullSecret", loc)
		nodes = append(nodes, sn)
		edges = append(edges, edge)
	}

	if firstConsumerID != "" {
		owner, oe := ownerEdge(firstConsumerID, ns)
		nodes = append(nodes, owner)
		edges = append(edges, oe)
	}

	return nodes, edges
}

func (s *k8sScanner) consumerNode(ns, kind, name, container string) graph.Node {
	canonicalKey := fmt.Sprintf("k8s:%s/%s/%s#%s", ns, kind, name, container)
	return graph.Node{
		ID:   graph.NodeID(graph.NodeConsumer, canonicalKey),
		Type: graph.NodeConsumer,
		Name: fmt.Sprintf("%s/%s/%s [%s]", ns, kind, name, container),
		Attrs: map[string]string{
			"surface":   "k8s",
			"kind":      kind,
			"namespace": ns,
			"container": container,
		},
	}
}

// secretEdge builds the name-keyed Secret node and a structural edge
// Consumer → Secret (directed, confidence 1.0) of the given type.
func (s *k8sScanner) secretEdge(consumerID, secretName string, et graph.EdgeType, ev string, loc graph.Location) (graph.Node, graph.Edge) {
	sn, sid := secretNodeByName(secretName)
	edge := graph.Edge{
		ID:         graph.EdgeID(consumerID, sid, et),
		Src:        consumerID,
		Dst:        sid,
		Type:       et,
		Direction:  graph.Directed,
		Confidence: 1.0,
		Provenance: graph.Provenance{
			RuleID:        string(et),
			Evidence:      []string{ev},
			Locations:     []graph.Location{loc},
			MatchedTokens: []string{secretName},
		},
	}
	return sn, edge
}

// ownerEdge builds the namespace Owner node and a consumer → owner owned_by
// edge (directed, conf 1.0).
func ownerEdge(consumerID, ns string) (graph.Node, graph.Edge) {
	ownerID := graph.NodeID(graph.NodeOwner, "ns:"+ns)
	owner := graph.Node{
		ID:    ownerID,
		Type:  graph.NodeOwner,
		Name:  ns,
		Attrs: map[string]string{"kind": "namespace"},
	}
	edge := graph.Edge{
		ID:         graph.EdgeID(consumerID, ownerID, graph.EdgeOwnedBy),
		Src:        consumerID,
		Dst:        ownerID,
		Type:       graph.EdgeOwnedBy,
		Direction:  graph.Directed,
		Confidence: 1.0,
		Provenance: graph.Provenance{
			RuleID:        string(graph.EdgeOwnedBy),
			Evidence:      []string{"metadata.namespace"},
			MatchedTokens: []string{ns},
		},
	}
	return owner, edge
}

// envSecretKeyRefs returns secret names from container env[].valueFrom.secretKeyRef.
func envSecretKeyRefs(c map[string]any) []string {
	var out []string
	env, _ := c["env"].([]any)
	for _, e := range env {
		em, ok := e.(map[string]any)
		if !ok {
			continue
		}
		vf, _ := em["valueFrom"].(map[string]any)
		ref, _ := vf["secretKeyRef"].(map[string]any)
		if n, _ := ref["name"].(string); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// envFromSecretRefs returns secret names from container envFrom[].secretRef.
func envFromSecretRefs(c map[string]any) []string {
	var out []string
	envFrom, _ := c["envFrom"].([]any)
	for _, e := range envFrom {
		em, ok := e.(map[string]any)
		if !ok {
			continue
		}
		ref, _ := em["secretRef"].(map[string]any)
		if n, _ := ref["name"].(string); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// volumeSecrets returns secret names from spec.volumes[].secret.secretName.
func volumeSecrets(spec map[string]any) []string {
	var out []string
	vols, _ := spec["volumes"].([]any)
	for _, v := range vols {
		vm, ok := v.(map[string]any)
		if !ok {
			continue
		}
		sec, _ := vm["secret"].(map[string]any)
		if n, _ := sec["secretName"].(string); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// imagePullSecrets returns secret names from spec.imagePullSecrets[].name.
func imagePullSecrets(spec map[string]any) []string {
	var out []string
	ips, _ := spec["imagePullSecrets"].([]any)
	for _, p := range ips {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if n, _ := pm["name"].(string); n != "" {
			out = append(out, n)
		}
	}
	return out
}

func (s *k8sScanner) scanSecret(doc map[string]any, rel string) ([]graph.Node, []graph.Edge) {
	name := metaName(doc)
	if name == "" {
		return nil, nil
	}
	node, _ := secretNodeByName(name)

	// KEY NAMES ONLY by default: never decode data:/stringData:. Only when
	// FingerprintInline is set do we read values, hash them, and discard the raw.
	if s.opts.FingerprintInline {
		if fp := s.fingerprintInlineSecret(doc); fp != "" {
			node.Fingerprint = fp
		}
	}
	return []graph.Node{node}, nil
}

// fingerprintInlineSecret decodes inline data:/stringData: values, computes the
// HMAC fingerprint of the FIRST decodable value, and discards the raw literal.
// The raw value is never returned, stored, or logged (§4.4).
func (s *k8sScanner) fingerprintInlineSecret(doc map[string]any) string {
	data, _ := doc["data"].(map[string]any)
	for _, v := range data {
		enc, ok := v.(string)
		if !ok {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			continue
		}
		fp := normalize.Fingerprint(s.opts.Salt, string(raw))
		// raw goes out of scope here and is never persisted.
		return fp
	}
	stringData, _ := doc["stringData"].(map[string]any)
	for _, v := range stringData {
		raw, ok := v.(string)
		if !ok {
			continue
		}
		return normalize.Fingerprint(s.opts.Salt, raw)
	}
	return ""
}

// secretNodeByStoreKey builds a Secret node keyed `store:<backend-key>` so an
// AWS/Vault scanner can attach to the same identity in v1.1 (§5.3).
func secretNodeByStoreKey(key string) (graph.Node, string) {
	canonicalKey := "store:" + normalize.IdentityName(key)
	id := graph.NodeID(graph.NodeSecret, canonicalKey)
	return graph.Node{
		ID:    id,
		Type:  graph.NodeSecret,
		Name:  key,
		Attrs: map[string]string{"backend_key": key},
	}, id
}

func (s *k8sScanner) scanExternalSecret(doc map[string]any, rel string) ([]graph.Node, []graph.Edge) {
	ns := metaNamespace(doc)
	name := metaName(doc)
	spec, _ := doc["spec"].(map[string]any)
	if spec == nil {
		return nil, nil
	}
	target, _ := spec["target"].(map[string]any)
	targetName, _ := target["name"].(string)
	if targetName == "" {
		// No materialized Secret to pivot on; nothing structural to emit.
		return nil, nil
	}

	remoteKeys := externalSecretRemoteKeys(spec)

	canonicalKey := fmt.Sprintf("k8s:%s/ExternalSecret/%s", ns, name)
	consumer := graph.Node{
		ID:   graph.NodeID(graph.NodeConsumer, canonicalKey),
		Type: graph.NodeConsumer,
		Name: fmt.Sprintf("%s/ExternalSecret/%s", ns, name),
		Attrs: map[string]string{
			"surface":         "k8s",
			"kind":            "ExternalSecret",
			"namespace":       ns,
			"target":          targetName,
			"remote_ref_keys": strings.Join(remoteKeys, ","),
		},
	}

	// Pivot: the materialized k8s Secret, keyed by target.name — the SAME key a
	// workload's injects/mounts edge resolves to (§6 reference-chain).
	pivot, pivotID := secretNodeByName(targetName)
	loc := graph.Location{File: rel, Surface: "k8s"}
	syncEdge := graph.Edge{
		ID:         graph.EdgeID(consumer.ID, pivotID, graph.EdgeSyncs),
		Src:        consumer.ID,
		Dst:        pivotID,
		Type:       graph.EdgeSyncs,
		Direction:  graph.Directed,
		Confidence: 1.0,
		Provenance: graph.Provenance{
			RuleID:        string(graph.EdgeSyncs),
			Evidence:      []string{"spec.target.name"},
			Locations:     []graph.Location{loc},
			MatchedTokens: []string{targetName},
		},
	}

	nodes := []graph.Node{consumer, pivot}
	edges := []graph.Edge{syncEdge}

	// Store-keyed backend node per remoteRef key + a references edge
	// ExternalSecret -> store:<key>. This edge is what the reference-chain rule
	// (§6) pivots on: store:<key> <-references- ExternalSecret -syncs-> pivot k8s
	// Secret <-injects/mounts- workload. Without it the 0.90 rule is dead against
	// real scan output (it would only fire on hand-built test graphs).
	for _, k := range remoteKeys {
		sn, snID := secretNodeByStoreKey(k)
		nodes = append(nodes, sn)
		edges = append(edges, graph.Edge{
			ID:         graph.EdgeID(consumer.ID, snID, graph.EdgeReferences),
			Src:        consumer.ID,
			Dst:        snID,
			Type:       graph.EdgeReferences,
			Direction:  graph.Directed,
			Confidence: 1.0,
			Provenance: graph.Provenance{
				RuleID:        string(graph.EdgeReferences),
				Evidence:      []string{"spec.data[].remoteRef.key"},
				Locations:     []graph.Location{loc},
				MatchedTokens: []string{k},
			},
		})
	}

	owner, oe := ownerEdge(consumer.ID, ns)
	nodes = append(nodes, owner)
	edges = append(edges, oe)

	return nodes, edges
}

// externalSecretRemoteKeys collects backend keys from spec.data[].remoteRef.key
// and spec.dataFrom[].extract.key / spec.dataFrom[].find (best-effort).
func externalSecretRemoteKeys(spec map[string]any) []string {
	var out []string
	data, _ := spec["data"].([]any)
	for _, d := range data {
		dm, ok := d.(map[string]any)
		if !ok {
			continue
		}
		ref, _ := dm["remoteRef"].(map[string]any)
		if k, _ := ref["key"].(string); k != "" {
			out = append(out, k)
		}
	}
	dataFrom, _ := spec["dataFrom"].([]any)
	for _, d := range dataFrom {
		dm, ok := d.(map[string]any)
		if !ok {
			continue
		}
		ext, _ := dm["extract"].(map[string]any)
		if k, _ := ext["key"].(string); k != "" {
			out = append(out, k)
		}
	}
	return out
}

func (s *k8sScanner) scanNamespace(doc map[string]any) ([]graph.Node, []graph.Edge) {
	name := metaName(doc)
	if name == "" {
		return nil, nil
	}
	canonicalKey := "ns:" + name
	return []graph.Node{{
		ID:    graph.NodeID(graph.NodeOwner, canonicalKey),
		Type:  graph.NodeOwner,
		Name:  name,
		Attrs: map[string]string{"kind": "namespace"},
	}}, nil
}

// metaName extracts metadata.name; "" if absent.
func metaName(doc map[string]any) string {
	meta, _ := doc["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	return name
}

// metaNamespace extracts metadata.namespace, defaulting to "default".
func metaNamespace(doc map[string]any) string {
	meta, _ := doc["metadata"].(map[string]any)
	ns, _ := meta["namespace"].(string)
	if ns == "" {
		return "default"
	}
	return ns
}

// secretNodeByName builds a Secret node keyed by its identity-canonical k8s
// secret name (§4.1: name-keyed Secret). Returns the node and its id.
func secretNodeByName(name string) (graph.Node, string) {
	canonical := normalize.IdentityName(name)
	id := graph.NodeID(graph.NodeSecret, canonical)
	return graph.Node{
		ID:   id,
		Type: graph.NodeSecret,
		Name: name,
	}, id
}

// podContainers returns the container maps for a workload, navigating the
// kind-specific path to the pod spec (CronJob nests under jobTemplate, Pod is
// a bare spec, the rest sit under template.spec).
func podContainers(doc map[string]any, kind string) []map[string]any {
	spec := podSpec(doc, kind)
	if spec == nil {
		return nil
	}
	raw, _ := spec["containers"].([]any)
	var out []map[string]any
	for _, c := range raw {
		if cm, ok := c.(map[string]any); ok {
			out = append(out, cm)
		}
	}
	return out
}

// podSpec navigates to the PodSpec map for a given workload kind.
func podSpec(doc map[string]any, kind string) map[string]any {
	spec, _ := doc["spec"].(map[string]any)
	if spec == nil {
		return nil
	}
	switch kind {
	case "Pod":
		return spec
	case "CronJob":
		jt, _ := spec["jobTemplate"].(map[string]any)
		jtSpec, _ := jt["spec"].(map[string]any)
		tmpl, _ := jtSpec["template"].(map[string]any)
		return mapAt(tmpl, "spec")
	default: // Deployment, StatefulSet, DaemonSet, Job
		tmpl, _ := spec["template"].(map[string]any)
		return mapAt(tmpl, "spec")
	}
}

func mapAt(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	v, _ := m[key].(map[string]any)
	return v
}
