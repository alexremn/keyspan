// internal/graph/blastradius_test.go
package graph

import (
	"testing"
)

// brSecret builds a secret node carrying an optional fingerprint attr.
func brSecret(name, fp string) Node {
	return Node{
		ID:          NodeID(NodeSecret, name),
		Type:        NodeSecret,
		Name:        name,
		Fingerprint: fp,
		Attrs:       map[string]string{},
	}
}

func brConsumer(key string) Node {
	return Node{ID: NodeID(NodeConsumer, key), Type: NodeConsumer, Name: key, Attrs: map[string]string{}}
}

func brOwner(key string) Node {
	return Node{ID: NodeID(NodeOwner, key), Type: NodeOwner, Name: key, Attrs: map[string]string{}}
}

func brCorrelate(a, b Node, conf float64) Edge {
	return Edge{
		ID:         EdgeID(a.ID, b.ID, EdgeCorrelates),
		Src:        a.ID,
		Dst:        b.ID,
		Type:       EdgeCorrelates,
		Direction:  Undirected,
		Confidence: conf,
	}
}

func brStructural(consumer, secret Node, t EdgeType) Edge {
	return Edge{
		ID:         EdgeID(consumer.ID, secret.ID, t),
		Src:        consumer.ID,
		Dst:        secret.ID,
		Type:       t,
		Direction:  Directed,
		Confidence: 1.0,
	}
}

func brOwnedBy(res, owner Node) Edge {
	return Edge{
		ID:         EdgeID(res.ID, owner.ID, EdgeOwnedBy),
		Src:        res.ID,
		Dst:        owner.ID,
		Type:       EdgeOwnedBy,
		Direction:  Directed,
		Confidence: 1.0,
	}
}

func brConsumerIDs(r QueryResult) map[string]ConsumerHit {
	m := map[string]ConsumerHit{}
	for _, c := range r.Consumers {
		m[c.Node.ID] = c
	}
	return m
}

func brClusterHas(r QueryResult, id string) bool {
	for _, n := range r.Cluster {
		if n.ID == id {
			return true
		}
	}
	return false
}

// TestGraphResolveRefByNameFpFinding covers the four ref grammars.
func TestGraphResolveRefByNameFpFinding(t *testing.T) {
	g := New()
	s := brSecret("aws_key", "deadbeef")
	g.AddNode(s)
	f := Node{ID: NodeID(NodeFinding, "gitleaks:loc1"), Type: NodeFinding, Name: "gitleaks:loc1", Attrs: map[string]string{}}
	g.AddNode(f)

	id, cands, err := g.ResolveRef("name:aws_key")
	if err != nil || id != s.ID || len(cands) != 0 {
		t.Fatalf("name ref: id=%q cands=%d err=%v", id, len(cands), err)
	}

	id, _, err = g.ResolveRef("fp:deadbeef")
	if err != nil || id != s.ID {
		t.Fatalf("fp ref: id=%q err=%v", id, err)
	}

	id, _, err = g.ResolveRef("finding:" + f.ID)
	if err != nil || id != f.ID {
		t.Fatalf("finding ref: id=%q err=%v", id, err)
	}
}

// TestGraphResolveRefBareFallsBackNameThenFp covers bare refs.
func TestGraphResolveRefBareFallsBackNameThenFp(t *testing.T) {
	g := New()
	named := brSecret("token", "")
	fpOnly := brSecret("other", "cafef00d")
	g.AddNode(named)
	g.AddNode(fpOnly)

	id, _, err := g.ResolveRef("token")
	if err != nil || id != named.ID {
		t.Fatalf("bare name: id=%q err=%v", id, err)
	}
	id, _, err = g.ResolveRef("cafef00d")
	if err != nil || id != fpOnly.ID {
		t.Fatalf("bare fp fallback: id=%q err=%v", id, err)
	}
}

// TestGraphResolveRefMultiMatchReturnsCandidates: same name across two surfaces.
func TestGraphResolveRefMultiMatchReturnsCandidates(t *testing.T) {
	g := New()
	// Two secret nodes that share the same name -> deliberately distinct ids.
	a := Node{ID: "id-a", Type: NodeSecret, Name: "dup", Attrs: map[string]string{}}
	b := Node{ID: "id-b", Type: NodeSecret, Name: "dup", Attrs: map[string]string{}}
	g.AddNode(a)
	g.AddNode(b)

	id, cands, err := g.ResolveRef("name:dup")
	if err == nil {
		t.Fatalf("expected multi-match error, got id=%q", id)
	}
	if len(cands) != 2 {
		t.Fatalf("candidates = %d, want 2", len(cands))
	}
}

func TestGraphResolveRefNoMatch(t *testing.T) {
	g := New()
	if _, _, err := g.ResolveRef("name:nope"); err == nil {
		t.Fatal("expected no-match error")
	}
}

// TestGraphBlastRadiusMaximinPicksHigherBottleneck:
// start - 0.9 - mid - 0.9 - far  vs  start - 0.95 - far (direct).
// The widest path to far has bottleneck 0.95, not 0.9.
func TestGraphBlastRadiusMaximinPicksHigherBottleneck(t *testing.T) {
	g := New()
	start := brSecret("start", "")
	mid := brSecret("mid", "")
	far := brSecret("far", "")
	g.AddNode(start)
	g.AddNode(mid)
	g.AddNode(far)
	g.AddEdge(brCorrelate(start, mid, 0.90))
	g.AddEdge(brCorrelate(mid, far, 0.90))
	g.AddEdge(brCorrelate(start, far, 0.95))

	// A consumer hangs off far so we can read its path confidence.
	c := brConsumer("gha:wf.yml#job.step")
	g.AddNode(c)
	g.AddEdge(brStructural(c, far, EdgeReferences))

	r := g.BlastRadius(start.ID, 0.50)
	hits := brConsumerIDs(r)
	hit, ok := hits[c.ID]
	if !ok {
		t.Fatalf("consumer off far not reached; hits=%v", hits)
	}
	if hit.Confidence != 0.95 {
		t.Errorf("path confidence = %v, want 0.95 (widest path)", hit.Confidence)
	}
}

// TestGraphBlastRadiusThresholdFilters drops a low-confidence branch.
func TestGraphBlastRadiusThresholdFilters(t *testing.T) {
	g := New()
	start := brSecret("start", "")
	weak := brSecret("weak", "")
	g.AddNode(start)
	g.AddNode(weak)
	g.AddEdge(brCorrelate(start, weak, 0.55))

	c := brConsumer("gha:wf.yml#job.weak")
	g.AddNode(c)
	g.AddEdge(brStructural(c, weak, EdgeReferences))

	r := g.BlastRadius(start.ID, 0.60)
	if brClusterHas(r, weak.ID) {
		t.Error("weak node (0.55 < 0.60) should be filtered from cluster")
	}
	if _, ok := brConsumerIDs(r)[c.ID]; ok {
		t.Error("consumer off filtered node must not appear")
	}
}

// TestGraphBlastRadiusCycleSafe: a correlate cycle must terminate.
func TestGraphBlastRadiusCycleSafe(t *testing.T) {
	g := New()
	a := brSecret("a", "")
	b := brSecret("b", "")
	cN := brSecret("c", "")
	g.AddNode(a)
	g.AddNode(b)
	g.AddNode(cN)
	g.AddEdge(brCorrelate(a, b, 0.90))
	g.AddEdge(brCorrelate(b, cN, 0.90))
	g.AddEdge(brCorrelate(cN, a, 0.90))

	r := g.BlastRadius(a.ID, 0.50)
	if len(r.Cluster) != 3 {
		t.Errorf("cluster len = %d, want 3 (cycle visited once each)", len(r.Cluster))
	}
}

// TestGraphBlastRadiusMultiHopBottleneck: far reached only via 0.90/0.70 chain.
func TestGraphBlastRadiusMultiHopBottleneck(t *testing.T) {
	g := New()
	start := brSecret("start", "")
	mid := brSecret("mid", "")
	far := brSecret("far", "")
	g.AddNode(start)
	g.AddNode(mid)
	g.AddNode(far)
	g.AddEdge(brCorrelate(start, mid, 0.90))
	g.AddEdge(brCorrelate(mid, far, 0.70))

	c := brConsumer("gha:wf.yml#job.far")
	g.AddNode(c)
	g.AddEdge(brStructural(c, far, EdgeInjects))

	r := g.BlastRadius(start.ID, 0.50)
	hit, ok := brConsumerIDs(r)[c.ID]
	if !ok {
		t.Fatal("consumer off far not reached")
	}
	if hit.Confidence != 0.70 {
		t.Errorf("bottleneck = %v, want 0.70", hit.Confidence)
	}
	if hit.Band != BandMedium {
		t.Errorf("band = %q, want medium for 0.70", hit.Band)
	}
}

// TestGraphBlastRadiusCollectsOwners follows owned_by from consumer and secret.
func TestGraphBlastRadiusCollectsOwners(t *testing.T) {
	g := New()
	start := brSecret("start", "")
	g.AddNode(start)
	c := brConsumer("gha:wf.yml#job.step")
	g.AddNode(c)
	g.AddEdge(brStructural(c, start, EdgeReferences))

	owner := brOwner("team:@org/sre")
	g.AddNode(owner)
	g.AddEdge(brOwnedBy(c, owner))

	r := g.BlastRadius(start.ID, 0.50)
	hit := brConsumerIDs(r)[c.ID]
	if len(hit.Owners) != 1 || hit.Owners[0].ID != owner.ID {
		t.Errorf("owners = %+v, want one sre owner", hit.Owners)
	}
}
