// SPDX-License-Identifier: Apache-2.0

// internal/scan/gha.go
package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/alexremn/keyspan/internal/graph"
	"github.com/alexremn/keyspan/internal/normalize"

	yaml "gopkg.in/yaml.v3"
)

const (
	ghaSurface           = "gha"
	ghaReferenceRuleID   = "gha-reference"
	ghaEnvIndirectRuleID = "gha-env-indirection"
	ghaWorkflowsRelpath  = ".github/workflows"
)

// secretsExprRe matches a single `${{ secrets.NAME }}` expression and captures NAME.
var secretsExprRe = regexp.MustCompile(`\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}`)

// envExprRe matches a single `${{ env.NAME }}` expression and captures NAME.
var envExprRe = regexp.MustCompile(`\$\{\{\s*env\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}`)

type ghaScanner struct{}

func newGHAScanner() *ghaScanner { return &ghaScanner{} }

func (s *ghaScanner) Name() string { return ghaSurface }

// workflow is the minimal shape of a GitHub Actions workflow we read.
type workflow struct {
	Env  map[string]yaml.Node `yaml:"env"`
	Jobs map[string]ghaJob    `yaml:"jobs"`
}

type ghaJob struct {
	Env   map[string]yaml.Node `yaml:"env"`
	Steps []ghaStep            `yaml:"steps"`
}

type ghaStep struct {
	ID   string               `yaml:"id"`
	Name string               `yaml:"name"`
	Run  string               `yaml:"run"`
	Env  map[string]yaml.Node `yaml:"env"`
	With map[string]yaml.Node `yaml:"with"`
}

func (s *ghaScanner) Scan(ctx context.Context, root string) ([]graph.Node, []graph.Edge, error) {
	wfDir := filepath.Join(root, ghaWorkflowsRelpath)
	entries, err := os.ReadDir(wfDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("gha: read workflows dir: %w", err)
	}

	var nodes []graph.Node
	var edges []graph.Edge
	seenNode := map[string]bool{}
	seenEdge := map[string]bool{}

	addNode := func(n graph.Node) {
		if seenNode[n.ID] {
			return
		}
		seenNode[n.ID] = true
		nodes = append(nodes, n)
	}
	addEdge := func(e graph.Edge) {
		if seenEdge[e.ID] {
			return
		}
		seenEdge[e.ID] = true
		edges = append(edges, e)
	}

	for _, entry := range entries {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		if entry.IsDir() || !isYAMLFile(entry.Name()) {
			continue
		}
		fullPath := filepath.Join(wfDir, entry.Name())
		relpath := filepath.ToSlash(filepath.Join(ghaWorkflowsRelpath, entry.Name()))
		if err := scanWorkflowFile(fullPath, relpath, addNode, addEdge); err != nil {
			return nil, nil, err
		}
	}

	// Fold CODEOWNERS ownership into the same gha surface result.
	coNodes, coEdges, err := scanCodeowners(root)
	if err != nil {
		return nil, nil, err
	}
	for _, n := range coNodes {
		addNode(n)
	}
	for _, e := range coEdges {
		addEdge(e)
	}

	return nodes, edges, nil
}

func isYAMLFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")
}

func scanWorkflowFile(
	fullPath, relpath string,
	addNode func(graph.Node),
	addEdge func(graph.Edge),
) error {
	raw, err := os.ReadFile(fullPath)
	if err != nil {
		return fmt.Errorf("gha: read %s: %w", relpath, err)
	}
	var wf workflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		logSkip(relpath, 0, "yaml-parse")
		return nil
	}

	// Workflow-level env: key -> secret name (only when value is exactly a secrets.* expr).
	wfEnv := envSecretMap(wf.Env)

	jobNames := sortedKeys(wf.Jobs)
	for _, jobName := range jobNames {
		job := wf.Jobs[jobName]
		jobEnv := mergeEnv(wfEnv, envSecretMap(job.Env))
		for idx, step := range job.Steps {
			stepName := stepLabel(step, idx)
			consumerKey := fmt.Sprintf("gha:%s#%s.%s", relpath, jobName, stepName)
			consumerID := graph.NodeID(graph.NodeConsumer, consumerKey)
			addNode(graph.Node{
				ID:    consumerID,
				Type:  graph.NodeConsumer,
				Name:  consumerKey,
				Attrs: map[string]string{"surface": ghaSurface, "file": relpath, "job": jobName, "step": stepName},
			})

			stepEnv := mergeEnv(jobEnv, envSecretMap(step.Env))

			// Direct secrets.* references.
			for _, secretName := range directSecretRefs(step) {
				emitSecretReference(consumerID, secretName, relpath, ghaReferenceRuleID, addNode, addEdge)
			}

			// One-hop env indirection: env.KEY where KEY resolves to a secret.
			for _, secretName := range envIndirectRefs(step, stepEnv) {
				emitSecretReference(consumerID, secretName, relpath, ghaEnvIndirectRuleID, addNode, addEdge)
			}
		}
	}
	return nil
}

// directSecretRefs returns the distinct secret names directly referenced by a step
// via `${{ secrets.NAME }}` in its `with:` values and `run:` script.
func directSecretRefs(step ghaStep) []string {
	found := map[string]bool{}
	collect := func(text string) {
		for _, m := range secretsExprRe.FindAllStringSubmatch(text, -1) {
			found[m[1]] = true
		}
	}
	collect(step.Run)
	for _, v := range step.With {
		collect(scalarText(v))
	}
	return sortedSet(found)
}

func emitSecretReference(
	consumerID, secretRawName, relpath, ruleID string,
	addNode func(graph.Node),
	addEdge func(graph.Edge),
) {
	canonical := normalize.IdentityName(secretRawName)
	secretID := graph.NodeID(graph.NodeSecret, canonical)
	addNode(graph.Node{
		ID:    secretID,
		Type:  graph.NodeSecret,
		Name:  secretRawName,
		Attrs: map[string]string{},
	})
	edgeID := graph.EdgeID(consumerID, secretID, graph.EdgeReferences)
	var evidence string
	if ruleID == ghaEnvIndirectRuleID {
		evidence = fmt.Sprintf("env key resolves to secrets.%s in %s", secretRawName, relpath)
	} else {
		evidence = fmt.Sprintf("secrets.%s referenced in %s", secretRawName, relpath)
	}
	addEdge(graph.Edge{
		ID:         edgeID,
		Src:        consumerID,
		Dst:        secretID,
		Type:       graph.EdgeReferences,
		Direction:  graph.Directed,
		Confidence: 1.0,
		Provenance: graph.Provenance{
			RuleID:        ruleID,
			Evidence:      []string{evidence},
			Locations:     []graph.Location{{File: relpath, Surface: ghaSurface}},
			MatchedTokens: []string{secretRawName},
		},
	})
}

// envSecretMap returns env-key -> secret-name for entries whose value is exactly
// a single `${{ secrets.NAME }}` expression. Non-secret env values are ignored.
func envSecretMap(env map[string]yaml.Node) map[string]string {
	out := map[string]string{}
	for k, v := range env {
		text := scalarText(v)
		m := secretsExprRe.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		out[k] = m[1]
	}
	return out
}

// mergeEnv layers child env over parent env (child wins), returning a new map.
func mergeEnv(parent, child map[string]string) map[string]string {
	out := make(map[string]string, len(parent)+len(child))
	for k, v := range parent {
		out[k] = v
	}
	for k, v := range child {
		out[k] = v
	}
	return out
}

// envIndirectRefs returns distinct secret names reached via one hop of `${{ env.KEY }}`
// where KEY is bound (at step/job/workflow scope) to a secrets.* expression.
func envIndirectRefs(step ghaStep, env map[string]string) []string {
	found := map[string]bool{}
	collect := func(text string) {
		for _, m := range envExprRe.FindAllStringSubmatch(text, -1) {
			if secretName, ok := env[m[1]]; ok {
				found[secretName] = true
			}
		}
	}
	collect(step.Run)
	for _, v := range step.With {
		collect(scalarText(v))
	}
	return sortedSet(found)
}

// scalarText renders a yaml.Node value to a string for expression scanning.
func scalarText(n yaml.Node) string {
	if n.Kind == yaml.ScalarNode {
		return n.Value
	}
	return ""
}

func stepLabel(step ghaStep, idx int) string {
	if step.ID != "" {
		return step.ID
	}
	if step.Name != "" {
		return step.Name
	}
	return fmt.Sprintf("step%d", idx)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// logSkip records a skipped/out-of-scope record by location only — never the raw content.
func logSkip(file string, line int, reason string) {
	if line > 0 {
		fmt.Fprintf(os.Stderr, "keyspan: skip %s:%d (%s)\n", file, line, reason)
		return
	}
	fmt.Fprintf(os.Stderr, "keyspan: skip %s (%s)\n", file, reason)
}
