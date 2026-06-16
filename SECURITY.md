# Security Policy

## Supported Versions

keyspan is pre-1.0. Until the first stable release, only the latest tagged
release receives security fixes.

| Version | Supported |
|---------|-----------|
| latest release | yes |
| older tags | no |

## Reporting a Vulnerability

Please report security issues **privately** via GitHub Security Advisories
("Report a vulnerability" on the repository's Security tab), or by email to
`security@keyspan.dev` if advisories are unavailable.

Do **not** open a public issue for a vulnerability.

**Response SLA:**

- Acknowledgement within **3 business days**.
- Triage and initial assessment within **10 business days**.
- Coordinated disclosure once a fix is available; we credit reporters who want it.

## Sensitive Artifacts

keyspan is "read-only" with respect to your secrets and infrastructure, but the
artifacts it **writes** are sensitive and must be handled as confidential:

- **`keyspan.db`** enumerates secret names, consumers, file locations, and
  fingerprints. It is written `0600`. **Never commit it** — the default
  `.gitignore` excludes `*.db`.
- **Report files** (`--out`, exported HTML/JSON/DOT) can enumerate the same
  topology. Treat them as you would an inventory of your secrets.
- Locations (`File:Line`) are **omitted by default** in JSON/DOT/HTML output;
  enabling `--include-locations` makes reports more sensitive.
- On public repositories, the GitHub Action masks secret names and guards
  itself behind explicit opt-in, because a blast-radius comment can leak infra
  topology.

## Honest Persistence Statement

keyspan stores **fingerprints, not raw values**. A value-fingerprint is
`HMAC-SHA-256(db_salt, value)`, truncated to 128 bits; `db_salt` is a 256-bit
random value generated per database. The raw literal is discarded immediately
after the fingerprint is computed — it is never written to any table,
provenance field, or log. An automated invariant test
(`internal/security/invariant_test.go`) asserts that known secret values appear
in no DB byte, renderer output, or log line.

**Residual risk (stated, not hidden):** an attacker who obtains a specific
`keyspan.db` also obtains its salt, and can therefore brute-force the
fingerprint of a **low-entropy** secret. Mitigations: keyspan only fingerprints
values a detector already flagged as a secret (generally high-entropy), the DB
is `0600` and gitignore-guided, and inline manifest values are not fingerprinted
unless you pass `--fingerprint-inline`. Fingerprints exist to **correlate**, not
to be a vault. Treat `keyspan.db` as confidential.
