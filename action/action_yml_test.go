// SPDX-License-Identifier: Apache-2.0

// action/action_yml_test.go
package action_test

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// actionManifest mirrors the parts of a composite action.yml we assert on.
type actionManifest struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Inputs      map[string]struct {
		Description string `yaml:"description"`
		Required    bool   `yaml:"required"`
		Default     string `yaml:"default"`
	} `yaml:"inputs"`
	Runs struct {
		Using string `yaml:"using"`
		Steps []struct {
			Name  string            `yaml:"name"`
			Shell string            `yaml:"shell"`
			Run   string            `yaml:"run"`
			Env   map[string]string `yaml:"env"`
		} `yaml:"steps"`
	} `yaml:"runs"`
}

func TestAction71ManifestIsCompositeWithRequiredInputs(t *testing.T) {
	// Arrange
	raw, err := os.ReadFile("action.yml")
	if err != nil {
		t.Fatalf("read action.yml: %v", err)
	}

	// Act
	var m actionManifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal action.yml: %v", err)
	}

	// Assert: composite runner.
	if m.Runs.Using != "composite" {
		t.Fatalf("runs.using = %q, want composite", m.Runs.Using)
	}

	// Assert: every documented input exists with the spec'd defaults.
	wantInputs := map[string]string{
		"path":              "", // no default; required-ish, defaulted to "."
		"db":                "", // checked below explicitly
		"min-confidence":    "0.50",
		"report":            "", // optional findings file
		"reveal-names":      "false",
		"include-locations": "false",
	}
	for name, wantDefault := range wantInputs {
		in, ok := m.Inputs[name]
		if !ok {
			t.Fatalf("missing input %q", name)
		}
		if wantDefault != "" && in.Default != wantDefault {
			t.Errorf("input %q default = %q, want %q", name, in.Default, wantDefault)
		}
		if in.Description == "" {
			t.Errorf("input %q has empty description", name)
		}
	}

	if got := m.Inputs["path"].Default; got != "." {
		t.Errorf("input path default = %q, want %q", got, ".")
	}
	if got := m.Inputs["db"].Default; got != "${{ runner.temp }}/keyspan.db" {
		t.Errorf("input db default = %q, want runner.temp keyspan.db", got)
	}

	// Assert: the security defaults are masked.
	if m.Inputs["reveal-names"].Default != "false" {
		t.Errorf("reveal-names must default to false")
	}
	if m.Inputs["include-locations"].Default != "false" {
		t.Errorf("include-locations must default to false")
	}

	// Assert: the step pipeline exists (build, scan, optional ingest, blast-radius).
	var steps []string
	for _, s := range m.Runs.Steps {
		steps = append(steps, s.Name)
		if s.Shell != "bash" {
			t.Errorf("step %q shell = %q, want bash", s.Name, s.Shell)
		}
	}
	wantSteps := []string{
		"Build keyspan",
		"Scan and ingest",
		"Blast radius PR comment",
	}
	if len(steps) != len(wantSteps) {
		t.Fatalf("steps = %v, want %v", steps, wantSteps)
	}
	for i, want := range wantSteps {
		if steps[i] != want {
			t.Errorf("step[%d] = %q, want %q", i, steps[i], want)
		}
	}

	// Assert: the final step invokes the entrypoint and threads inputs through env.
	final := m.Runs.Steps[len(m.Runs.Steps)-1]
	wantEnv := []string{
		"KEYSPAN_DB", "KEYSPAN_PATH", "KEYSPAN_MIN_CONFIDENCE",
		"KEYSPAN_REVEAL_NAMES", "KEYSPAN_INCLUDE_LOCATIONS", "KEYSPAN_REPORT",
	}
	for _, k := range wantEnv {
		if _, ok := final.Env[k]; !ok {
			t.Errorf("final step missing env %q", k)
		}
	}
}
