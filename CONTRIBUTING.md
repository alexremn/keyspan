# Contributing to keyspan

Thanks for helping. keyspan is a security tool, so correctness and conservative
defaults matter more than feature velocity.

## Development

Requires Go 1.26+.

```bash
make build     # build the binary into ./bin
make test      # go test -race ./...
make lint      # golangci-lint run
make cover     # coverage report (target: 80%+)
make run ARGS="blast-radius name:FOO"
```

## Ground rules

- **TDD.** Write a failing test first. The correlation engine and store changes
  must include positive, negative, and confidence-boundary cases.
- **`go test -race` must pass.** Tests are race-friendly by design.
- **Never persist or log a raw secret value.** New scanners/renderers must keep
  the §16 security invariant green. Fingerprint then discard.
- **Conservative correlation.** Do not collapse Secret nodes; correlation is a
  confidence-scored edge, never a node merge.
- Keep files focused (~200–400 lines). Add an SPDX header
  (`// SPDX-License-Identifier: Apache-2.0`) to every new `.go` file.

## Commits & PRs

- Conventional commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).
- CI must be green (build, `go test -race -cover`, `golangci-lint`) before review.
- By contributing you agree your contribution is licensed under Apache-2.0.
