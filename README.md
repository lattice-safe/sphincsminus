# sphincsminus

[![CI](https://github.com/lattice-safe/sphincsminus/actions/workflows/ci.yml/badge.svg)](https://github.com/lattice-safe/sphincsminus/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/lattice-safe/sphincsminus.svg)](https://pkg.go.dev/github.com/lattice-safe/sphincsminus)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Pure-Go implementation of **SPHINCS⁻ (SPHINCS minus)**, an EVM-oriented,
stateless hash-based signature scheme: a SPHINCS+ / SLH-DSA-style
construction (FIPS 205 §4.2 uncompressed ADRS) re-instantiated over
Ethereum's native `keccak256`, using **WOTS+C** (Winternitz one-time
signatures with a digit-sum grind replacing the usual checksum) and
**FORS+C** (forest of random subsets with a forced-zero last tree, so its
authentication path can be omitted) to shrink both signature size and
on-chain verification gas. It is designed to be byte-compatible with the
Solidity verifiers described in the ethresear.ch post
["SPHINCS minus: Efficient Stateless Post-Quantum Signature Verification on the EVM"](https://ethresear.ch/)
and implemented at [github.com/nconsigny/SPHINCS-](https://github.com/nconsigny/SPHINCS-):
signatures produced by this package verify unchanged, byte-for-byte, in
that repository's compiled bytecode, and this package's `Verify` mirrors
that bytecode's control flow exactly.

## Status & support

* **Version 0.1.0** — pre-1.0: the Go API may still change between minor
  versions; the wire format for a given parameter-set name (C7, C9, C10,
  C11, C13) never changes (see [`docs/RELEASING.md`](docs/RELEASING.md)
  for the full policy).
* **Supported Go**: 1.22 and later. CI tests 1.22.x, 1.23.x, 1.24.x, and
  1.25.x.
* **Platforms tested**: CI runs the full suite on Linux, and Go 1.25 on
  macOS and Windows; it also cross-compiles (build-only) for
  linux/amd64, linux/arm64, linux/386, windows/amd64, darwin/arm64, and
  js/wasm.
* **Security policy**: see [`SECURITY.md`](SECURITY.md) for supported
  versions, how to report a vulnerability, and scope.
* **Research-grade, not FIPS 205, unaudited** — see
  [Security](#security) below before using this for anything that
  matters.

## Features

* Key generation, deterministic signing, and verification for all five
  keccak C-series parameter sets (C7, C9, C10, C11, C13).
* Byte-compatible with the upstream Solidity verifiers — the same
  (key, message) produces the same signature as the reference Rust/Python
  signers, and that signature verifies both in this package and on-chain.
* Deterministic signing: the same (key, message) always yields the same
  signature (the R-grind and WOTS+C count-grind are both seeded and
  searched sequentially from 0).
* Parallel signing: FORS and WOTS leaf generation fan out over
  `runtime.GOMAXPROCS(0)` goroutines; `Signer` additionally caches the
  top-layer hypertree subtree across repeated `Sign` calls.
* Pure Go with **zero external dependencies**: Keccak-256 is an in-repo, allocation-free sponge built on the BSD-licensed Keccak-f[1600] permutation from `golang.org/x/crypto` (see `LICENSE-THIRD-PARTY`).
  No CGO, no assembly.

## Parameters

`n` is the node size in bytes (always 16); `h`/`d` is the hypertree height
split into `d` layers; `a`/`k` are the FORS+C tree height and count; `w`/`l`
are the WOTS+C base and chain count. See `docs/SPEC.md` §2 for the full
derivation of `sig bytes` from these.

| Variant | h  | d | a  | k  | w | l  | target_sum | sig bytes | per-key budget (2^h) | upstream-reported pure verify gas |
|---------|----|---|----|----|---|----|------------|-----------|----------------------|------------------------------------|
| C7      | 24 | 2 | 16 | 8  | 8 | 43 | 151        | 3704      | 2^24                 | 127K                               |
| C9      | 20 | 2 | 12 | 11 | 8 | 43 | 208        | 3816      | 2^20                 | ~117K                              |
| C10     | 18 | 2 | 11 | 13 | 8 | 43 | 205        | 4008      | 2^18                 | 115K                               |
| C11     | 16 | 2 | 11 | 13 | 8 | 43 | 203        | 3976      | 2^16                 | 116K                               |
| C13     | 22 | 2 | 19 | 7  | 8 | 43 | 208        | 3688      | 2^22                 | 105K                               |

**C13 is the recommended default**: smallest signature, lowest reported
on-chain verify gas, and the largest per-key signing budget among the
size-optimized sets. C11 is the fastest to sign/verify in this package and
is a good choice for tests and examples. The gas figures above are as
reported upstream for a pure `verify()` call against the compiled
Solidity bytecode; see `evmoracle/` below for how this repository
independently measures the same numbers by executing that bytecode.

## Install

```bash
go get github.com/lattice-safe/sphincsminus
```

## Usage

### Go API

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/lattice-safe/sphincsminus"
)

func main() {
	sk, err := sphincsminus.GenerateKey(sphincsminus.C13)
	if err != nil {
		panic(err)
	}

	// The message is always exactly 32 bytes -- an EVM hash.
	var msg [32]byte
	copy(msg[:], []byte("hello, sphincs minus"))

	sig, err := sk.Sign(msg[:])
	if err != nil {
		panic(err)
	}

	fmt.Println(sk.PublicKey.Verify(msg[:], sig)) // true

	// Repeated signing under the same key: use a Signer to cache the
	// top-layer hypertree subtree instead of rebuilding it every call.
	signer, err := sphincsminus.NewSigner(sk)
	if err != nil {
		panic(err)
	}
	_, _ = signer.Sign(msg[:])

	// A C13/C7 sign can take seconds (the FORS+C R-grind); SignContext
	// lets a caller bound or cancel that wait instead of blocking.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = signer.SignContext(ctx, msg[:])
}
```

Keys and signatures round-trip to bytes for storage/transport:

```go
pkBytes := sk.PublicKey.Bytes()          // 32 bytes: pkSeed16‖pkRoot16
skBytes := sk.Bytes()                    // 64 bytes: skSeed32‖pkSeed16‖pkRoot16
pk, _ := sphincsminus.ParsePublicKey(sphincsminus.C13, pkBytes)
sk2, _ := sphincsminus.ParsePrivateKey(sphincsminus.C13, skBytes)

// Always zeroize a private key's secret seed once you're done with it.
defer sk.Zeroize()
```

See `example_test.go` for runnable examples, including how
`PublicKey.SeedWord()`/`RootWord()` map onto the on-chain `bytes32`
arguments and how a `verify(bytes32,bytes32,bytes32,bytes)` call's
calldata is assembled.

### CLI (`cmd/sphincsminus`)

```bash
go install github.com/lattice-safe/sphincsminus/cmd/sphincsminus@latest

# Generate a key (random by default; JSON to stdout).
sphincsminus keygen -params C13 > key.json

# Sign a 32-byte message with that key.
sphincsminus sign -params C13 -key key.json -msg 0xdeadbeef...

# Verify a signature against a public key and message.
sphincsminus verify -params C13 -pk 0x... -msg 0xdeadbeef... -sig 0x...

# Print the upstream ABI-encoded (pkSeed, pkRoot, sig) hex -- the same
# format the reference signer.py/signer-c13 print -- for Foundry FFI tests.
sphincsminus vector -params C13 -msg 0xdeadbeef...

# List every supported parameter set.
sphincsminus params
```

Exit codes: `0` valid/success, `1` invalid signature (`verify` only),
`2` usage/parse error. Run `sphincsminus <command> -h` for full flag
documentation.

## Interoperability

* **Wire formats** (`docs/SPEC.md` §3, §11): a public key is
  `pkSeed[16]‖pkRoot[16]` (32 bytes); a private key is
  `skSeed[32]‖pkSeed[16]‖pkRoot[16]` (64 bytes); a signature is
  `R‖FORS secrets‖FORS auth paths‖(WOTS+C chains‖count‖XMSS auth path)×d`,
  with every node stored as its 16 significant bytes.
* **On-chain (`bytes32`) encoding**: `PublicKey.SeedWord()`/`RootWord()`
  return the same 16 bytes top-aligned in a 32-byte word (low 16 bytes
  zero — "N_MASK form"), matching exactly what the Solidity verifiers'
  `bytes32 pkSeed`/`bytes32 pkRoot` arguments expect. A non-canonical key
  (non-zero low bytes) is rejected on-chain.
* **`vector` / reference tooling**: `sphincsminus vector` mirrors the
  upstream `signer.py <variant> <msg>` / `signer-c13 sign <msg>` tools
  byte-for-byte — same key derivation (SPEC §3.2), same signature, same
  `abi.encode(bytes32, bytes32, bytes)` framing — so Foundry `ffi` tests
  written against those Python/Rust tools can shell out to this binary
  instead.
* **`evmoracle/`** is a separate nested Go module
  (`github.com/lattice-safe/sphincsminus/evmoracle`, its own `go.mod`
  with a `replace` back to this module) that loads the real, upstream
  -compiled Solidity verifier bytecode and runs it inside go-ethereum's
  EVM (`core/vm/runtime`) as the final compatibility oracle: every
  reference vector and every Go-signed signature is checked to verify
  `true` both via this package's `Verify` and via the actual on-chain
  bytecode, and the mutation/failure semantics of SPEC §12 (revert vs.
  `false`, which differs by variant) are checked against the real
  bytecode rather than assumed. It is isolated in its own module purely
  to keep the (large) go-ethereum dependency tree out of this library's
  `go.sum`; `go get github.com/lattice-safe/sphincsminus` never pulls it
  in.

## Thread safety & cancellation

* `PublicKey` and `Params` (including the predefined `C7`/`C9`/`C10`/`C11`/`C13`)
  are immutable after construction and safe to share and read concurrently
  from any number of goroutines.
* `PrivateKey.Sign` and `Signer.Sign` are safe to call concurrently — from
  the same `*Signer`/`*PrivateKey` or different ones — with no external
  locking required.
* `(*PrivateKey).SignContext(ctx, msg)` and `(*Signer).SignContext(ctx, msg)`
  behave like `Sign`/`Sign` but check `ctx` while grinding, so a long C13
  (or C7) sign can be cancelled or bounded with a timeout instead of
  blocking the caller until it finishes.

## Performance

Measured on an Apple M1 Max (10 cores):

| Operation | C11      | C13         |
|-----------|----------|-------------|
| Keygen    | 7.6 ms   | 51 ms       |
| Sign      | 64 ms    | ~2.6–3.5 s  |
| Verify    | 158 µs   | 154 µs      |

Signing cost is dominated by building the `k-1` FORS trees of `2^a` leaves
each (every leaf is a PRF call plus a hash) and by the R-grind (expected
`2^a` attempts to hit FORS+C's forced-zero condition), both of which scale
with `2^a`; the WOTS+C count-grind is comparatively cheap; C13's much larger `a` (19 vs. C11's 11) is why its sign
time is markedly higher despite a smaller `k`. Verify cost instead scales
with signature size and tree heights actually walked, which is why C13
(fewer, larger FORS trees; shorter hypertree) verifies faster than C11
despite being the "stronger" grind. Run `go test -bench . -benchmem ./`
to reproduce these numbers on your own hardware.

## Security

* **Research-grade construction, not FIPS 205.** SPHINCS⁻ trades some of
  standard SLH-DSA's conservatism (an explicit WOTS checksum, a full FORS
  authentication path per tree) for smaller signatures and cheaper on-chain
  verification. It has **not** been independently audited.
* **Bounded per-key signing budget.** Each key may safely produce at most
  `2^h` signatures before the security argument no longer holds: `2^24`
  for C7, `2^22` for C13, `2^16` for C11 (see the parameter table above
  for the rest). This package does not track how many signatures a key
  has produced — callers who need that must track it themselves.
* **Deterministic signing.** The same (key, message) pair always produces
  the same signature; there is no per-signature randomness to leak.
* **Keep `skSeed` secret**, and call `PrivateKey.Zeroize()` once a key is
  no longer needed. `DeriveKeyReference`/the CLI's `-material` flag derive
  a key entirely from public material and exist only for cross-testing
  against reference vectors — never use them for a key that needs to stay
  secret.
* **Not for production funds.** This is a research/interop implementation
  of an experimental scheme; do not use it to protect value or
  safety-critical systems without an independent security review
  appropriate to your threat model.

## Relation to `lattice-slh-dsa-go`

`sphincsminus` targets the experimental, EVM-tuned keccak C-series
(WOTS+C, FORS+C, byte-compatible with `github.com/nconsigny/SPHINCS-`'s
Solidity verifiers). Its sibling,
[`lattice-slh-dsa-go`](https://github.com/lattice-safe/lattice-slh-dsa-go),
implements standard **FIPS 205 SLH-DSA** instead — the standardized,
conservative (full WOTS+ checksum, full FORS auth paths) hash-based
signature scheme. The two packages mirror each other's flat-package
layout and API shape, but are not wire-compatible with one another:
reach for `lattice-slh-dsa-go` when you need FIPS 205 compliance, and for
`sphincsminus` when you need cheap keccak256 on-chain verification.

## Development

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for dev setup, test commands,
the rule that `docs/SPEC.md` is the wire-format authority, and how to
regenerate upstream reference vectors. Common tasks are wired up in the
[`Makefile`](Makefile): `make build`, `make test`, `make test-slow`,
`make race`, `make lint`, `make fuzz`, `make cover`, `make bench`,
`make oracle` (the `evmoracle` module), `make cross` (cross-compile),
and `make tidy`. See [`docs/RELEASING.md`](docs/RELEASING.md) for the
release process and versioning policy.

## License

MIT — see `LICENSE`.
