# AGENTS.md

Guidance for AI coding agents working in this repository.

## Overview

`certinfo` is a small Go library (`github.com/smallstep/certinfo`) that renders X.509 certificates and certificate signing requests as human-readable text, in a format similar to `openssl x509 -text`. It is a maintained fork of [grantae/certinfo](https://github.com/grantae/certinfo) (MIT; original copyright retained in `LICENSE`). On top of the upstream output it decodes selected vendor and standards OIDs: Smallstep provisioner / managed-endpoint / managed-device extensions, Sigstore (Fulcio) OIDs, TCG TPM EK credential attributes, Yubico PIV attestation extensions, SCTs, and post-quantum algorithm names (ML-DSA, SLH-DSA, composite signatures). The public `step` CLI uses it for `step certificate inspect`.

There is no binary; the package is the whole repo. Dependencies are the standard library plus `golang.org/x/crypto`, `google/certificate-transparency-go`, and `google/go-cmp` (tests only).

## Commands

```bash
go build ./...          # compile (Makefile `build` target is a no-op)
make test               # gotestsum with coverage (what CI runs); go test ./... also works
make race               # tests with -race
make lint               # golangci-lint (config fetched from smallstep/workflows) + govulncheck
make fmt                # goimports -w on all .go files
make bootstrap          # install golangci-lint, govulncheck, gotestsum
```

```bash
go test -run TestCertInfoLeaf1 .     # run a single test (single package, so path is ".")
go test -run 'TestSigstore|TestNoCN' .
```

Build and tests need no env vars, network, Docker, or private modules. `make test` leaves a `coverage.out` in the repo root (gitignored).

CI (`.github/workflows/ci.yml`) calls the shared `smallstep/workflows` `goCI` workflow: lint (golangci-lint, `go mod tidy -diff`), govulncheck, CodeQL, and the test command above on both `stable` and `oldstable` Go. Keep `go.mod`/`go.sum` tidy or the lint job fails.

## Architecture

```
certinfo/
├── certinfo.go          # Core: OID tables, ASN.1 structs, all four exported functions
├── certformat.go        # certificateShort / certificateRequestShort types behind the *ShortText functions
├── yubico.go            # Yubico PIV attestation extension decoding
├── mldsa_go127.go       # //go:build go1.27  — real crypto/mldsa key handling
├── mldsa_stub.go        # //go:build !go1.27 — stubs so the package builds on older Go
├── certinfo_test.go     # Golden-file tests (see below)
├── certformat_test.go
└── test_certs/          # Fixtures: PEM inputs + expected .text / .short outputs, OpenSSL cfgs
```

Public API is four functions, all `(string, error)`:

- `CertificateText(*x509.Certificate)` and `CertificateRequestText(*x509.CertificateRequest)` — full OpenSSL-style dump.
- `CertificateShortText` and `CertificateRequestShortText` — abbreviated summary.

Everything else is unexported. The long-form printers walk the raw TBS structure (`tbsCertificate` / `tbsCertificateRequest` parsed with `encoding/asn1` and `cryptobyte`) so they can show fields Go's `x509` package drops, then iterate `cert.Extensions` and dispatch on OID. Unknown extensions fall through to a generic hex/rune dump (`printRunes`).

## Testing

Tests are golden-file comparisons. Each fixture in `test_certs/` has a PEM input and one or more expected outputs:

| Input | Expected output | Compared by |
|-------|-----------------|-------------|
| `*.cert.pem`, `*.crt` | `*.cert.text`, `*.crt.text` | `testPair` (cmp.Diff) |
| `*.csr.pem`, `*.csr` | `*.csr.text` | `testPair` |
| any of the above | `*.short`, `*.text.short` | `testPairShort` (bytes.Equal) |

When output changes intentionally, update the `.text` / `.short` files by hand or by capturing the new output; there is no `-update` flag. Any change to `certinfo.go` formatting almost always requires touching fixtures, so review those diffs carefully in PRs.

ML-DSA certificate fixtures (`ML-DSA-*.crt`) are only checked on Go >= 1.27, gated by `x509MLDSA != -1` in `TestUnknownCrypto`; the DigiCert ML-DSA CSR fixtures run everywhere. If you are on an older Go, that half of the test silently skips.

`test_certs/make-certs.sh` and `new-keys.sh` regenerate the OpenSSL-based fixtures (`root1`, `leaf1`..`leaf5`). DSA/ECDSA signing is non-deterministic, so regenerating CSRs changes them; see `test_certs/README` for the caveats (including the known `Signature Algorithm: 0` line in `leaf2.csr.text`).

## Conventions

- Plain `fmt.Errorf` and `errors.New`; no `pkg/errors`, no logging, no CLI framework, no config.
- Output is built into a `bytes.Buffer` with `fmt.Fprintf`; keep indentation and field names byte-identical to existing fixtures (the tests are exact-match).
- New OIDs go in the `var` blocks at the top of `certinfo.go` with a comment linking the defining spec; add a fixture exercising them.
- Go version support: `go.mod` says 1.24, CI tests `stable` and `oldstable`. Anything that needs a newer stdlib API must be split behind build tags like the `mldsa_*.go` pair.
- `goimports` is run via `make fmt`; note its `-local` flag is set to `github.com/golangci/golangci-lint`, which is a leftover and does not group this module's imports specially.
- Standard library only where possible; adding a dependency to a library this small needs justification in the PR.
