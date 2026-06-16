// SPDX-License-Identifier: Apache-2.0

// Package graph defines keyspan's node/edge domain model and traversal.
package graph

import (
	"crypto/sha256"
	"encoding/hex"
)

// NodeType enumerates the kinds of graph nodes.
type NodeType string

const (
	NodeSecret   NodeType = "secret"
	NodeConsumer NodeType = "consumer"
	NodeOwner    NodeType = "owner"
	NodeFinding  NodeType = "finding"
)

// EdgeType enumerates structural and heuristic edge kinds.
type EdgeType string

const (
	EdgeDetectedAs EdgeType = "detected_as"
	EdgeReferences EdgeType = "references"
	EdgeInjects    EdgeType = "injects"
	EdgeMounts     EdgeType = "mounts"
	EdgePulls      EdgeType = "pulls"
	EdgeSyncs      EdgeType = "syncs"
	EdgeOwnedBy    EdgeType = "owned_by"
	EdgeCorrelates EdgeType = "correlates"
)

// Direction governs how an edge is traversed.
type Direction string

const (
	Directed   Direction = "directed"
	Undirected Direction = "undirected"
)

// Band is a coarse confidence bucket.
type Band string

const (
	BandHigh   Band = "high"
	BandMedium Band = "medium"
	BandLow    Band = "low"
)

// Rule confidences, default threshold, and band cut-points (design spec §6).
const (
	ConfFingerprintMatch = 0.95
	ConfReferenceChain   = 0.90
	ConfNameMatch        = 0.55
	DefaultMinConfidence = 0.50
	BandHighThreshold    = 0.85
	BandMediumThreshold  = 0.60
)

// Location is a file/line reference for a piece of evidence.
type Location struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Surface string `json:"surface"`
}

// Provenance is the structured "show your work" attached to every edge.
// No field ever holds a raw secret value (invariant, design spec §4.6).
type Provenance struct {
	RuleID        string     `json:"rule_id"`
	Evidence      []string   `json:"evidence"`
	Locations     []Location `json:"locations"`
	MatchedTokens []string   `json:"matched_tokens"`
}

// Node is a vertex: a secret, consumer, owner, or finding.
type Node struct {
	ID          string
	Type        NodeType
	Name        string
	Fingerprint string
	Attrs       map[string]string
}

// Edge connects two nodes with a confidence-scored, provenanced relation.
type Edge struct {
	ID         string
	Src        string
	Dst        string
	Type       EdgeType
	Direction  Direction
	Confidence float64
	Provenance Provenance
}

// ConsumerHit is a consumer reachable from a queried secret cluster.
type ConsumerHit struct {
	Node       Node
	Confidence float64
	Band       Band
	Chain      []Edge
	Owners     []Node
}

// QueryResult is the pure output of a blast-radius query; renderers consume it.
type QueryResult struct {
	Start     Node
	Cluster   []Node
	Consumers []ConsumerHit
}

// NodeID returns the stable id hex(sha256(type ∥ 0x00 ∥ canonicalKey))[:32].
func NodeID(t NodeType, canonicalKey string) string {
	sum := sha256.Sum256([]byte(string(t) + "\x00" + canonicalKey))
	return hex.EncodeToString(sum[:])[:32]
}

// EdgeID returns the upsert-stable id hex(sha256(src ∥ 0x00 ∥ dst ∥ 0x00 ∥ type))[:32].
func EdgeID(src, dst string, t EdgeType) string {
	sum := sha256.Sum256([]byte(src + "\x00" + dst + "\x00" + string(t)))
	return hex.EncodeToString(sum[:])[:32]
}
