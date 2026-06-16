// SPDX-License-Identifier: Apache-2.0

// action/entrypoint_test.go
package action_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeKeyspan writes a tiny shell stub named "keyspan" into dir that, for a
// `blast-radius ... --format json` invocation, echoes the QueryResult fixture,
// and for any other subcommand exits 0. Returns the stub path.
func writeFakeKeyspan(t *testing.T, dir, fixtureJSON string) string {
	t.Helper()
	stub := filepath.Join(dir, "keyspan")
	body := "#!/usr/bin/env bash\n" +
		"set -euo pipefail\n" +
		"for a in \"$@\"; do\n" +
		"  if [ \"$a\" = \"blast-radius\" ]; then\n" +
		"    cat " + shellQuote(fixtureJSON) + "\n" +
		"    exit 0\n" +
		"  fi\n" +
		"done\n" +
		"exit 0\n"
	if err := os.WriteFile(stub, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake keyspan: %v", err)
	}
	return stub
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// runEntrypoint runs entrypoint.sh with a controlled env and returns the
// markdown written to the comment file plus the process exit code.
func runEntrypoint(t *testing.T, env map[string]string) (markdown string, exitCode int) {
	t.Helper()
	tmp := t.TempDir()

	fixture, err := filepath.Abs(filepath.Join("testdata", "blastradius_aws.json"))
	if err != nil {
		t.Fatalf("abs fixture: %v", err)
	}
	bin := writeFakeKeyspan(t, tmp, fixture)

	diff, err := filepath.Abs(filepath.Join("testdata", "diff_changed_files.txt"))
	if err != nil {
		t.Fatalf("abs diff: %v", err)
	}

	commentFile := filepath.Join(tmp, "comment.md")
	summaryFile := filepath.Join(tmp, "summary.md")
	script, err := filepath.Abs("entrypoint.sh")
	if err != nil {
		t.Fatalf("abs script: %v", err)
	}

	base := map[string]string{
		"KEYSPAN_BIN":               bin,
		"KEYSPAN_DB":                filepath.Join(tmp, "keyspan.db"),
		"KEYSPAN_PATH":              ".",
		"KEYSPAN_MIN_CONFIDENCE":    "0.50",
		"KEYSPAN_REVEAL_NAMES":      "false",
		"KEYSPAN_INCLUDE_LOCATIONS": "false",
		"KEYSPAN_REPORT":            "",
		"KEYSPAN_IS_PUBLIC":         "false",
		// Test seam: feed a static changed-files list and capture outputs.
		"KEYSPAN_DIFF_FILE":   diff,
		"KEYSPAN_COMMENT_OUT": commentFile,
		"GITHUB_STEP_SUMMARY": summaryFile,
		// Test seam: skip the network comment post.
		"KEYSPAN_SKIP_POST": "1",
	}
	for k, v := range env {
		base[k] = v
	}

	cmd := exec.Command("bash", script)
	cmd.Env = os.Environ()
	for k, v := range base {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run entrypoint: %v (output: %s)", err, out)
		}
	}

	md, rerr := os.ReadFile(commentFile)
	if rerr != nil && code == 0 {
		t.Fatalf("read comment file: %v (stdout: %s)", rerr, out)
	}
	return string(md), code
}

func TestEntrypoint72MaskedByDefaultHidesNamesAndLocations(t *testing.T) {
	// Arrange + Act
	md, code := runEntrypoint(t, nil)

	// Assert: clean exit.
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; markdown:\n%s", code, md)
	}

	// Assert: the known fixture secret NAME (lowercased, as keyspan stores it) is
	// masked out by default.
	if strings.Contains(md, "aws_access_key_id") {
		t.Errorf("masked comment leaked secret name aws_access_key_id:\n%s", md)
	}
	// Assert: the known fixture File:Line is omitted by default.
	if strings.Contains(md, "deploy.yml:42") {
		t.Errorf("masked comment leaked location deploy.yml:42:\n%s", md)
	}
	// Assert: aggregate signal (type + count + band) is still present.
	for _, want := range []string{"secret", "Consumer", "High", "consumer", "1"} {
		if !strings.Contains(md, want) {
			t.Errorf("masked comment missing aggregate token %q:\n%s", want, md)
		}
	}
}

func TestEntrypoint72RevealNamesShowsNamesWhenOptedIn(t *testing.T) {
	// Arrange + Act
	md, code := runEntrypoint(t, map[string]string{"KEYSPAN_REVEAL_NAMES": "true"})

	// Assert
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; markdown:\n%s", code, md)
	}
	if !strings.Contains(md, "aws_access_key_id") {
		t.Errorf("reveal-names=true should show secret name:\n%s", md)
	}
	// Locations still off because include-locations defaulted false.
	if strings.Contains(md, "deploy.yml:42") {
		t.Errorf("location leaked while include-locations=false:\n%s", md)
	}
}

func TestEntrypoint72IncludeLocationsShowsLocationsWhenOptedIn(t *testing.T) {
	// Arrange + Act
	md, code := runEntrypoint(t, map[string]string{
		"KEYSPAN_REVEAL_NAMES":      "true",
		"KEYSPAN_INCLUDE_LOCATIONS": "true",
	})

	// Assert
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; markdown:\n%s", code, md)
	}
	if !strings.Contains(md, "deploy.yml:42") {
		t.Errorf("include-locations=true should show location:\n%s", md)
	}
}

func TestEntrypoint72PublicRepoRequiresExplicitOptIn(t *testing.T) {
	// Arrange + Act: public repo + reveal-names without acknowledging the risk.
	md, code := runEntrypoint(t, map[string]string{
		"KEYSPAN_IS_PUBLIC":    "true",
		"KEYSPAN_REVEAL_NAMES": "true",
	})

	// Assert: the guard forces back to masked output and warns, but does not fail.
	if code != 0 {
		t.Fatalf("public-repo guard should warn, not fail; exit=%d md:\n%s", code, md)
	}
	if strings.Contains(md, "AWS_ACCESS_KEY_ID") {
		t.Errorf("public repo must mask names even with reveal-names=true:\n%s", md)
	}
	if !strings.Contains(md, "public repository") {
		t.Errorf("expected a public-repo warning in the comment:\n%s", md)
	}
}

func TestEntrypoint72NoTouchedSecretsProducesCleanComment(t *testing.T) {
	// Arrange: a diff that touches no scanned surface.
	tmp := t.TempDir()
	empty := filepath.Join(tmp, "none.txt")
	if err := os.WriteFile(empty, []byte("README.md\n"), 0o644); err != nil {
		t.Fatalf("write empty diff: %v", err)
	}

	// Act
	md, code := runEntrypoint(t, map[string]string{"KEYSPAN_DIFF_FILE": empty})

	// Assert
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; md:\n%s", code, md)
	}
	if !strings.Contains(md, "No secret surfaces touched") {
		t.Errorf("expected clean no-op comment:\n%s", md)
	}
	if strings.Contains(md, "AWS_ACCESS_KEY_ID") {
		t.Errorf("clean comment must not contain any secret name:\n%s", md)
	}
}
