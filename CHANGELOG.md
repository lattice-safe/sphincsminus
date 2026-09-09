# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/) with
the pre-1.0 caveats described in [`docs/RELEASING.md`](docs/RELEASING.md).

## [Unreleased]

Nothing yet.

## [0.1.0] - 2026-09-09

Initial release.

### Added
* Key generation, deterministic signing, and verification for all five
  keccak C-series parameter sets: **C7, C9, C10, C11, C13** (WOTS+C /
  FORS+C over keccak256, FIPS 205 §4.2 uncompressed ADRS).
* Byte-compatibility with the upstream Solidity verifiers at
  [`nconsigny/SPHINCS-`](https://github.com/nconsigny/SPHINCS-): all 11
  reference vectors from the upstream Rust/Python signers verify, and
  signatures produced by this package verify unchanged both via this
  package's `Verify` and via the real, compiled verifier bytecode.
* Allocation-free keccak256 sponge (`keccak.go`) over the Keccak-f[1600]
  permutation vendored from `golang.org/x/crypto` (BSD, see
  `LICENSE-THIRD-PARTY`) — the package has **zero external dependencies**
  at the module level. No CGO, no assembly.
* `evmoracle`, a separate nested Go module that runs the upstream-compiled
  Solidity verifier bytecode inside go-ethereum's EVM as the final
  compatibility oracle, covering both the reference vectors and
  freshly-signed Go signatures, plus the SPEC §12 revert-vs-`false`
  mutation semantics per variant.
* `cmd/sphincsminus` CLI: `keygen`, `sign`, `verify`, `vector` (upstream
  ABI-encoded output for Foundry `ffi` interop), and `params`.
* Context-aware signing: `(*PrivateKey).SignContext(ctx, msg)` and
  `(*Signer).SignContext(ctx, msg)` cancel a long-running sign (dominated
  by the FORS+C R-grind, worst-case seconds on C13/C7) instead of
  blocking to completion.
* Validation hardening: a stricter `Params.Validate()`, with `Sign` and
  `Verify` rejecting an invalid `*Params` via an error/`false` return
  instead of panicking.
* Key zeroization: `(*PrivateKey).Zeroize()` and `(*Signer).Zeroize()`
  overwrite cached secret material once a key/signer is no longer needed.
* Parallel signing: FORS/WOTS leaf generation fans out across
  `runtime.GOMAXPROCS(0)` goroutines, and `Signer` caches the top-layer
  hypertree subtree across repeated `Sign` calls on the same key.

[Unreleased]: https://github.com/lattice-safe/sphincsminus/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/lattice-safe/sphincsminus/releases/tag/v0.1.0
