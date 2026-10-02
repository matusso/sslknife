# Development

```sh
make build          # ./sslknife with version information
make test           # unit and integration tests (local servers only, no Internet)
make test-race
make vet lint vuln  # go vet + gofmt, golangci-lint, govulncheck
make fuzz           # short fuzzing pass over all parsers (FUZZTIME=30s)
make docs           # regenerate docs/commands
make cross          # binaries for all release platforms in dist/
```

The web UI is plain ES modules in [`web/static`](../web/static), embedded in the
binary, with no build step. `web/test/smoke.mjs` runs it in jsdom against a
live server; CI does this automatically.

Architecture, the encrypted database design and the schema are in
[DESIGN.md](DESIGN.md); the roadmap is in [ROADMAP.md](ROADMAP.md). Releases
are described in [releasing.md](releasing.md).
