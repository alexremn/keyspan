// SPDX-License-Identifier: Apache-2.0

// action/example_workflow_test.go
package action_test

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// exampleWorkflow mirrors the parts of the example workflow we assert on.
type exampleWorkflow struct {
	On struct {
		PullRequest map[string]any `yaml:"pull_request"`
	} `yaml:"on"`
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]struct {
		RunsOn string `yaml:"runs-on"`
		Steps  []struct {
			Uses string            `yaml:"uses"`
			With map[string]string `yaml:"with"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func TestExample73WorkflowUsesActionWithSafeDefaults(t *testing.T) {
	// Arrange
	path := filepath.Join("..", "examples", "keyspan-action.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read example workflow: %v", err)
	}

	// Act
	var wf exampleWorkflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("unmarshal example workflow: %v", err)
	}

	// Assert: triggered on pull_request.
	if wf.On.PullRequest == nil {
		t.Fatalf("example workflow must trigger on pull_request")
	}

	// Assert: minimal write permission for commenting.
	if wf.Permissions["pull-requests"] != "write" {
		t.Errorf("permissions.pull-requests = %q, want write", wf.Permissions["pull-requests"])
	}

	// Assert: a job references the keyspan action and checks out the repo first.
	var sawCheckout, sawAction bool
	var withReveal string
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			switch step.Uses {
			case "actions/checkout@v4":
				sawCheckout = true
			case "alexremn/keyspan/action@v1":
				sawAction = true
				withReveal = step.With["reveal-names"]
			}
		}
	}
	if !sawCheckout {
		t.Errorf("example workflow must check out the repo (actions/checkout@v4)")
	}
	if !sawAction {
		t.Errorf("example workflow must reference alexremn/keyspan/action@v1")
	}
	// Assert: masked-by-default posture is preserved (no reveal-names override,
	// or an explicit false).
	if withReveal == "true" {
		t.Errorf("example workflow must not set reveal-names: true (masked default)")
	}
}
