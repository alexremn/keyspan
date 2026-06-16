// internal/scan/k8s.go
package scan

import (
	"context"
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
	return []graph.Node{node}, nil
}

func (s *k8sScanner) scanExternalSecret(doc map[string]any, rel string) ([]graph.Node, []graph.Edge) {
	return nil, nil
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
