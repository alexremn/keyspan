// internal/normalize/normalize_test.go
package normalize

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestNormalizeIdentityNameLowercasesAndTrimsOnly(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"  AWS_ACCESS_KEY_ID  ", "aws_access_key_id"},
		{"Token", "token"},
		{"aws-access-key-id", "aws-access-key-id"}, // separators preserved
		{"PROD_DB_PASSWORD", "prod_db_password"},   // no prefix strip at identity grade
	}
	for _, tc := range cases {
		if got := IdentityName(tc.in); got != tc.want {
			t.Errorf("IdentityName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeNameGradeDefaultStripsSeparators(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"AWS_ACCESS_KEY_ID", "awsaccesskeyid"},
		{"aws-access-key-id", "awsaccesskeyid"}, // matches the underscore form
		{"My.Secret.Key", "mysecretkey"},
		{"  Trim_Me  ", "trimme"},
	}
	for _, tc := range cases {
		if got := NameGrade(tc.in, false); got != tc.want {
			t.Errorf("NameGrade(%q,false) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeNameGradeAggressiveStripsAffixes(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"prod_db_password", "dbpassword"},    // prod_ prefix stripped
		{"staging_api_token", "api"},          // staging_ prefix + _token suffix
		{"dev_session_key", "session"},        // dev_ prefix + _key suffix
		{"user_id", "user"},                   // _id suffix
		{"client_secret", "client"},           // _secret suffix
	}
	for _, tc := range cases {
		if got := NameGrade(tc.in, true); got != tc.want {
			t.Errorf("NameGrade(%q,true) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeNameGradeAggressiveIsSupersetOfDefault(t *testing.T) {
	// A name with no enumerated affix should match the default grade.
	if NameGrade("randomname", true) != NameGrade("randomname", false) {
		t.Error("aggressive grade must equal default grade when no affix present")
	}
}

func TestNormalizeFingerprintMatchesHMACExactBytes(t *testing.T) {
	salt := []byte("0123456789abcdef0123456789abcdef")
	literal := "AKIAIOSFODNN7EXAMPLE"

	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(literal))
	want := hex.EncodeToString(mac.Sum(nil))[:32]

	got := Fingerprint(salt, literal)
	if got != want {
		t.Fatalf("Fingerprint = %q, want %q", got, want)
	}
	if len(got) != 32 {
		t.Fatalf("Fingerprint len = %d, want 32", len(got))
	}
}

func TestNormalizeFingerprintNoValueNormalization(t *testing.T) {
	salt := []byte("saltsaltsaltsalt")
	// Surrounding whitespace and case must NOT be normalized: distinct fingerprints.
	if Fingerprint(salt, " value ") == Fingerprint(salt, "value") {
		t.Error("Fingerprint must hash exact bytes, not a normalized form")
	}
	if Fingerprint(salt, "Value") == Fingerprint(salt, "value") {
		t.Error("Fingerprint must be case-sensitive (exact bytes)")
	}
}

func TestNormalizeFingerprintDeterministicPerSalt(t *testing.T) {
	a := Fingerprint([]byte("salt-a"), "v")
	b := Fingerprint([]byte("salt-b"), "v")
	if a == b {
		t.Error("different salts must yield different fingerprints")
	}
	if Fingerprint([]byte("salt-a"), "v") != a {
		t.Error("same salt+literal must be deterministic")
	}
}
