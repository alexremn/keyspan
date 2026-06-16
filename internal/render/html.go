// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	_ "embed"
	"html/template"
	"io"

	"github.com/alexremn/keyspan/internal/graph"
)

// cytoscapeJS is the pinned, vendored Cytoscape.js v3.34.0 UMD bundle (MIT,
// single self-contained file, no runtime deps). Embedded so the HTML report is
// fully offline and self-contained (§10).
//
//go:embed assets/cytoscape.min.js
var cytoscapeJS string

// htmlRenderer produces a single self-contained HTML report. The QueryResult is
// serialized to JSON, base64-encoded, and placed inside a
// <script type="application/json"> block — never in an executable HTML/JS
// context — then decoded client-side via atob+JSON.parse. This makes injection
// (e.g. a malicious node name containing </script>) inert (§10 breakout test).
type htmlRenderer struct{}

// htmlData is the page model. Cytoscape is injected via template.JS (trusted,
// vendored asset). Payload is template.JS-safe base64 text (alphabet has no HTML
// metacharacters), placed in a non-executable script type.
type htmlData struct {
	Cytoscape  template.JS
	PayloadB64 template.JS
}

var htmlTemplate = template.Must(template.New("keyspan").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>keyspan blast-radius</title>
<style>
  html,body{margin:0;height:100%;font-family:Helvetica,Arial,sans-serif}
  #cy{width:100%;height:100vh;display:block}
</style>
<script>{{.Cytoscape}}</script>
</head>
<body>
<div id="cy"></div>
<script type="application/json" id="keyspan-data">{{.PayloadB64}}</script>
<script>
(function(){
  var raw = document.getElementById('keyspan-data').textContent;
  var data = JSON.parse(atob(raw));
  var elements = [];
  function pushNode(n){ elements.push({ data: { id: n.id, label: n.name, ntype: n.type } }); }
  pushNode(data.start);
  (data.cluster||[]).forEach(pushNode);
  (data.consumers||[]).forEach(function(c){
    pushNode(c.node);
    (c.owners||[]).forEach(pushNode);
    (c.chain||[]).forEach(function(e){
      elements.push({ data: { id: e.id, source: e.src, target: e.dst, label: e.confidence.toFixed(2) } });
    });
  });
  var seen = {}, deduped = [];
  elements.forEach(function(el){ if(!seen[el.data.id]){ seen[el.data.id]=true; deduped.push(el); } });
  cytoscape({
    container: document.getElementById('cy'),
    elements: deduped,
    style: [
      { selector: 'node', style: { 'label': 'data(label)', 'background-color': '#7f8c8d', 'color':'#fff', 'text-valign':'center', 'font-size':'10px' } },
      { selector: 'node[ntype = "secret"]',   style: { 'background-color': '#e74c3c' } },
      { selector: 'node[ntype = "consumer"]', style: { 'background-color': '#3498db' } },
      { selector: 'node[ntype = "owner"]',    style: { 'background-color': '#2ecc71' } },
      { selector: 'node[ntype = "finding"]',  style: { 'background-color': '#f39c12' } },
      { selector: 'edge', style: { 'label':'data(label)','width':1,'line-color':'#95a5a6','target-arrow-color':'#95a5a6','target-arrow-shape':'triangle','curve-style':'bezier','font-size':'9px' } }
    ],
    layout: { name: 'breadthfirst', directed: true }
  });
})();
</script>
</body>
</html>
`))

func (htmlRenderer) Render(w io.Writer, r graph.QueryResult, opts Options) error {
	// Reuse the JSON renderer's exact projection so redaction (locations,
	// fingerprints) is identical across formats.
	var jsonBuf bytes.Buffer
	if err := (jsonRenderer{}).Render(&jsonBuf, r, opts); err != nil {
		return err
	}

	// Re-marshal compactly to keep the embedded payload small; the projection
	// already stripped fingerprints/locations.
	var compact bytes.Buffer
	if err := json.Compact(&compact, jsonBuf.Bytes()); err != nil {
		return err
	}

	payload := base64.StdEncoding.EncodeToString(compact.Bytes())
	return htmlTemplate.Execute(w, htmlData{
		Cytoscape:  template.JS(cytoscapeJS),
		PayloadB64: template.JS(payload),
	})
}
