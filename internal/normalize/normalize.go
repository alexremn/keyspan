// internal/normalize/normalize.go
// SPDX-License-Identifier: Apache-2.0

// Package normalize canonicalizes names and computes value fingerprints.
package normalize

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// aggressivePrefixes are stripped from a name-graded string under --aggressive-names.
var aggressivePrefixes = []string{"prod_", "staging_", "dev_"}

// aggressiveSuffixes are stripped from a name-graded string under --aggressive-names.
var aggressiveSuffixes = []string{"_id", "_key", "_token", "_secret"}

// IdentityName is identity-grade canonicalization (design spec §4.3):
// lowercase + trim surrounding whitespace ONLY. No separator or affix stripping.
func IdentityName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// NameGrade is fuzzy name-match normalization (design spec §6): lowercase, trim,
// strip '-', '_', '.'. When aggressive, enumerated prefixes/suffixes are stripped
// from the raw (still-separated) name before separators are removed.
func NameGrade(name string, aggressive bool) string {
	s := strings.ToLower(strings.TrimSpace(name))
	if aggressive {
		s = stripAffixes(s)
	}
	r := strings.NewReplacer("-", "", "_", "", ".", "")
	return r.Replace(s)
}

func stripAffixes(s string) string {
	for _, p := range aggressivePrefixes {
		if strings.HasPrefix(s, p) {
			s = strings.TrimPrefix(s, p)
			break
		}
	}
	for _, suf := range aggressiveSuffixes {
		if strings.HasSuffix(s, suf) {
			s = strings.TrimSuffix(s, suf)
			break
		}
	}
	return s
}

// Fingerprint returns hex(HMAC-SHA256(salt, []byte(literal)))[:32] over the EXACT
// bytes of literal — no value normalization (design spec §4.4).
func Fingerprint(salt []byte, literal string) string {
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(literal))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}
