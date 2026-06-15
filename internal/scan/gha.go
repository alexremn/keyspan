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
	ghaSurface          = "gha"
	ghaReferenceRuleID  = "gha-reference"
	ghaWorkflowsRelpath = ".github/workflows"
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
		// Tolerant: log file + error type only, never the raw record (it may carry a secret).
		logSkip(relpath, 0, "yaml-parse")
		return nil
	}

	jobNames := sortedKeys(wf.Jobs)
	for _, jobName := range jobNames {
		job := wf.Jobs[jobName]
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

			secretNames := directSecretRefs(step)
			for _, secretName := range secretNames {
				emitSecretReference(consumerID, secretName, relpath, addNode, addEdge)
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
	consumerID, secretRawName, relpath string,
	addNode func(graph.Node),
	addEdge func(graph.Edge),
) {
	secretName := normalize.IdentityName(secretRawName)
	secretID := graph.NodeID(graph.NodeSecret, secretName)
	addNode(graph.Node{
		ID:    secretID,
		Type:  graph.NodeSecret,
		Name:  secretName,
		Attrs: map[string]string{},
	})
	edgeID := graph.EdgeID(consumerID, secretID, graph.EdgeReferences)
	addEdge(graph.Edge{
		ID:         edgeID,
		Src:        consumerID,
		Dst:        secretID,
		Type:       graph.EdgeReferences,
		Direction:  graph.Directed,
		Confidence: 1.0,
		Provenance: graph.Provenance{
			RuleID:        ghaReferenceRuleID,
			Evidence:      []string{fmt.Sprintf("secrets.%s referenced in %s", secretRawName, relpath)},
			Locations:     []graph.Location{{File: relpath, Surface: ghaSurface}},
			MatchedTokens: []string{secretName},
		},
	})
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
