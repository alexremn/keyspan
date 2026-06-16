// SPDX-License-Identifier: Apache-2.0

// internal/graph/types_test.go
package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// expectNodeID recomputes the contract hash inside the test (no hand-coded vector).
func expectNodeID(t NodeType, canonicalKey string) string {
	sum := sha256.Sum256([]byte(string(t) + "\x00" + canonicalKey))
	return hex.EncodeToString(sum[:])[:32]
}

func expectEdgeID(src, dst string, t EdgeType) string {
	sum := sha256.Sum256([]byte(src + "\x00" + dst + "\x00" + string(t)))
	return hex.EncodeToString(sum[:])[:32]
}

func TestGraphNodeIDDeterministicAndLen32(t *testing.T) {
	got := NodeID(NodeSecret, "aws_access_key_id")
	again := NodeID(NodeSecret, "aws_access_key_id")
	if got != again {
		t.Fatalf("NodeID not deterministic: %q vs %q", got, again)
	}
	if len(got) != 32 {
		t.Fatalf("NodeID len = %d, want 32", len(got))
	}
	if got != expectNodeID(NodeSecret, "aws_access_key_id") {
		t.Fatalf("NodeID = %q, want recomputed %q", got, expectNodeID(NodeSecret, "aws_access_key_id"))
	}
}

func TestGraphNodeIDDistinctByTypeAndKey(t *testing.T) {
	a := NodeID(NodeSecret, "k")
	b := NodeID(NodeConsumer, "k")
	c := NodeID(NodeSecret, "k2")
	if a == b {
		t.Errorf("NodeID collided across types: %q", a)
	}
	if a == c {
		t.Errorf("NodeID collided across keys: %q", a)
	}
}

func TestGraphEdgeIDDeterministicAndLen32(t *testing.T) {
	got := EdgeID("src", "dst", EdgeReferences)
	if len(got) != 32 {
		t.Fatalf("EdgeID len = %d, want 32", len(got))
	}
	if got != expectEdgeID("src", "dst", EdgeReferences) {
		t.Fatalf("EdgeID = %q, want recomputed %q", got, expectEdgeID("src", "dst", EdgeReferences))
	}
}

func TestGraphEdgeIDDistinctByDirectionOfPair(t *testing.T) {
	if EdgeID("a", "b", EdgeReferences) == EdgeID("b", "a", EdgeReferences) {
		t.Error("EdgeID must distinguish src/dst order")
	}
	if EdgeID("a", "b", EdgeReferences) == EdgeID("a", "b", EdgeInjects) {
		t.Error("EdgeID must distinguish edge type")
	}
}

func TestGraphConstantsMatchContract(t *testing.T) {
	if ConfFingerprintMatch != 0.95 || ConfReferenceChain != 0.90 || ConfNameMatch != 0.55 {
		t.Error("rule confidence constants drifted from contract")
	}
	if DefaultMinConfidence != 0.50 {
		t.Errorf("DefaultMinConfidence = %v, want 0.50", DefaultMinConfidence)
	}
	if BandHighThreshold != 0.85 || BandMediumThreshold != 0.60 {
		t.Error("band thresholds drifted from contract")
	}
}
