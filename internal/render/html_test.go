// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
)

func TestRenderHTMLEmbedsCytoscapeAndBase64Data(t *testing.T) {
	res := renderTestFixtureResult()

	var buf bytes.Buffer
	if err := (htmlRenderer{}).Render(&buf, res, Options{IncludeLocations: false}); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	out := buf.String()

	// Self-contained: the embedded cytoscape bundle is present (its UMD factory
	// registers a global `cytoscape`).
	if !strings.Contains(out, "cytoscape") {
		t.Fatalf("expected embedded cytoscape in HTML output")
	}

	// Data injected as base64 in an application/json script block, read via atob.
	if !strings.Contains(out, `<script type="application/json" id="keyspan-data">`) {
		t.Fatalf("expected application/json data block, got:\n%s", out[:minInt(len(out), 800)])
	}
	if !strings.Contains(out, "atob(") || !strings.Contains(out, "JSON.parse(") {
		t.Fatalf("expected atob+JSON.parse decode path")
	}

	// Extract the base64 payload and confirm it decodes to JSON carrying the
	// secret name (proves data round-trips through the safe channel).
	re := regexp.MustCompile(`id="keyspan-data">([A-Za-z0-9+/=]+)</script>`)
	m := re.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("could not locate base64 payload in:\n%s", out)
	}
	decoded, err := base64.StdEncoding.DecodeString(m[1])
	if err != nil {
		t.Fatalf("payload is not valid base64: %v", err)
	}
	if !bytes.Contains(decoded, []byte("AWS_ACCESS_KEY_ID")) {
		t.Fatalf("decoded payload missing expected secret name: %s", decoded)
	}

	// Fingerprints never rendered, even inside the encoded payload.
	if bytes.Contains(decoded, []byte("deadbeefdeadbeefdeadbeefdeadbeef")) {
		t.Fatalf("fingerprint must never appear in HTML payload")
	}
}

func TestRenderHTMLScriptBreakoutIsNeutralized(t *testing.T) {
	res := renderTestFixtureResult()
	// Malicious node name attempting to break out of the script context.
	res.Start.Name = `</script><img src=x onerror=alert(1)>`
	res.Cluster[0].Name = res.Start.Name

	var buf bytes.Buffer
	if err := (htmlRenderer{}).Render(&buf, res, Options{}); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	out := buf.String()

	// Because the payload is base64-encoded, the raw breakout string MUST NOT
	// appear anywhere in the rendered HTML in executable form.
	if strings.Contains(out, "</script><img src=x onerror=alert(1)>") {
		t.Fatalf("XSS breakout string leaked into HTML unencoded:\n%s", out)
	}
	if strings.Contains(out, "onerror=alert(1)") {
		t.Fatalf("event-handler payload leaked into HTML unencoded:\n%s", out)
	}

	// The malicious name still round-trips inside the base64 payload (rendered
	// safely client-side, never as HTML).
	re := regexp.MustCompile(`id="keyspan-data">([A-Za-z0-9+/=]+)</script>`)
	m := re.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("could not locate base64 payload")
	}
	decoded, _ := base64.StdEncoding.DecodeString(m[1])
	if !bytes.Contains(decoded, []byte("onerror=alert(1)")) {
		t.Fatalf("expected malicious name preserved inside encoded payload")
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
