// SPDX-License-Identifier: Apache-2.0

// Package security holds the cross-cutting §16 security-invariant test: no raw
// secret value ever appears in the SQLite DB bytes, any renderer's output, any
// serialized node/edge, or any log line. It has no production code; the
// invariant is enforced entirely by invariant_test.go (package security_test).
package security
