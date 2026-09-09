# Implementation Plan — SPHINCS⁻ in Go

Planner: Claude Fable 5.1. Implementers: Claude Sonnet 5 worker agents, one per phase.
Every phase has a hard acceptance gate that the planner runs before the next phase starts.

## Goals

1. `go get github.com/lattice-safe/sphincsminus` gives keygen, **sign** and verify for
   the keccak C-series (C7, C9, C10, C11, C13) with signatures that the upstream
   Solidity verifiers accept unchanged.
2. Byte-identical output to the upstream Rust/Python signers for the same
   (key, message): signing is deterministic (R grind + WOTS+C count grind).
3. Practical signing speed in pure Go: C13 sign in single-digit seconds on a laptop
   (multi-core), C11 well under a second.
4. Verify is allocation-light, panic-free on adversarial input, and mirrors the
   on-chain checks exactly (length, forced-zero, digit sum, root).

Non-goals for v1: C12 plain SPHINCS+, SHA-256 / BLAKE2b twins, SLH-DSA-128-24 (that
is `lattice-slh-dsa-go` territory), JARDIN legacy layout, BIP-39 wallet derivation.

## Architecture

Flat package `sphincsminus` (mirrors `lattice-slh-dsa-go`), one nested test module.

```
go.mod                      module github.com/lattice-safe/sphincsminus (no external deps)
keccakf.go                  Keccak-f[1600] permutation vendored from x/crypto (BSD, LICENSE-THIRD-PARTY)
params.go                   Params struct; C7,C9,C10,C11,C13; derived sizes; Validate()
keccak.go                   fixed-size zero-alloc keccak256 helpers, word type, maskN
address.go                  ADRS builders (FIPS uncompressed 32 B) as [32]byte / setters
thash.go                    Th, ThPair, ThMulti, HMsg, WotsDigest
prf.go                      wotsSecret, forsSecret, grindR
wots.go                     WOTS+C: digits, findCount, keygen, sign, pkFromSig
merkle.go                   subtree build (parallel), auth path, computeRoot
fors.go                     FORS+C: tree build (parallel), sign, pkFromSig
sign.go                     signInternal (all layers), Sign
verify.go                   Verify (pure, mirrors Solidity control flow)
keys.go                     PublicKey / PrivateKey, encoding, GenerateKey, DeriveKeyReference
sphincsminus.go             package doc, errors, top-level API
cmd/sphincsminus/main.go    CLI: keygen | sign | verify | vector (reference-compatible ABI hex)
testdata/vectors/*.json     upstream reference vectors (C7, C9, C10, C11, C13)
evmoracle/                  nested module: runs Solidity bytecode in go-ethereum's EVM
evmoracle/testdata/*.bin-runtime  compiled upstream verifiers (solc 0.8.28, via_ir)
docs/SPEC.md                byte-level spec (authority)
docs/PLAN.md                this file
```

### Public API (Go)

```go
type Params struct { Name string; H, D, A, K, W, LogW, L, TargetSum int; ... }
var C7, C9, C10, C11, C13 *Params          // C13 recommended
func (p *Params) SigBytes() int             // etc.

type PublicKey  struct { Params *Params; Seed [16]byte; Root [16]byte }
type PrivateKey struct { Params *Params; SkSeed [32]byte; PublicKey }

func GenerateKey(p *Params) (*PrivateKey, error)                       // crypto/rand
func NewPrivateKeyFromSeeds(p *Params, skSeed [32]byte, pkSeed [16]byte) (*PrivateKey, error) // computes root
func DeriveKeyReference(p *Params, material [32]byte) (*PrivateKey, error) // §3.2 interop derivation

func (sk *PrivateKey) Sign(msg32 []byte) ([]byte, error)                // deterministic
func (pk *PublicKey) Verify(msg32, sig []byte) bool
func Verify(p *Params, pkSeed, pkRoot [16]byte, msg32, sig []byte) bool  // pure function

func (pk *PublicKey) Bytes() []byte / ParsePublicKey(p, b)               // 32 B
func (sk *PrivateKey) Bytes() []byte / ParsePrivateKey(p, b)             // 64 B
func (pk *PublicKey) SeedWord() [32]byte; RootWord() [32]byte           // top-aligned for Solidity ABI
func (sk *PrivateKey) Zeroize()

// Optional signer with cached top-layer subtree for repeated signing:
type Signer struct{...}; func NewSigner(sk *PrivateKey) *Signer; func (s *Signer) Sign(msg32 []byte) ([]byte, error)
```

### Internal representation

* `type word = [32]byte`. Node values are N_MASK words. Helpers: `maskN`, `wordFromBytes16`, `to16`.
* Keccak: in-repo allocation-free sponge (`keccak.go`) over the vendored permutation (`keccakf.go`);
  concrete type, no `hash.Hash` interface, so escape analysis keeps inputs/outputs on the stack (Phase 5, done).
* Parallelism: FORS leaf generation and WOTS leaf generation fan out over `runtime.GOMAXPROCS(0)` goroutines
  with chunked leaf ranges; tree levels are built sequentially per level (cheap relative to leaves).
* Memory: FORS tree for C13 has 2^19 leaves × 32 B = 16 MiB per level 0; building one tree at a time
  and keeping only the path needed keeps peak < 64 MiB. Store node arrays as `[]word` per level.

## Phases

### Phase 0 — Scaffold (planner, done)
go.mod, CLAUDE.md, docs/SPEC.md, testdata/vectors, evmoracle/testdata bytecode.

### Phase 1 — Primitives + Verify (worker: Sonnet 5)
Files: params.go, keccak.go, address.go, thash.go, prf.go, wots.go, merkle.go, fors.go, verify.go, keys.go (types + encoding + Verify only), sphincsminus.go.
Tests:
* `params_test.go`: derived sizes equal SPEC table for all five sets; invariant `k*a+h <= 256`.
* `prf_test.go`: KATs from SPEC §3.2 (pk_seed, sk_seed, wotsSecret, forsSecret).
* `address_test.go`: ADRS bytes for representative inputs (hand-computed from SPEC §4).
* `vectors_test.go`: every vector in `testdata/vectors/*.json` verifies `true`; flipping any single
  byte of R / a FORS secret / a WOTS chain / count / an auth node makes it `false`; wrong message `false`;
  wrong length `false`; verifying a C13 vector under C11 params `false`.
* Fuzz target `FuzzVerify` (never panics).
Gate: `go vet`, `go test ./...` green, all 11 reference vectors verify.

### Phase 2 — Signing + Keygen (worker: Sonnet 5)
Files: sign.go, keys.go (GenerateKey, NewPrivateKeyFromSeeds, DeriveKeyReference, Signer cache), wots.go/fors.go/merkle.go signing halves.
Tests:
* `sign_test.go`: for each vector with `keyDerivation: reference:*`, derive keys, assert `pkRoot` equals vector,
  sign the vector's message, assert **byte-identical** signature (this pins R grind, count grind, PRFs).
  C11/C10/C9 always run; C7/C13 run when `SPHINCSMINUS_SLOW=1` or under `-run TestSignVectorsSlow`.
* Roundtrip with random keys for C11 (fast) and every set under SLOW.
* `Signer` cache produces identical output to `PrivateKey.Sign`.
* Benchmarks: `BenchmarkSign{C11,C13}`, `BenchmarkVerify{C11,C13}`, `BenchmarkKeygenC13`.
Gate: all vector signatures byte-identical; C13 sign < 15 s on the dev machine (report the number).

### Phase 3 — EVM oracle + CLI (two workers in parallel: Sonnet 5)
3a `evmoracle/`: a working prototype exists at
   `/private/tmp/claude-502/-Users-suleymankardas-Desktop-lattice-safe-sphincsminus/12b77ce5-a1ab-47fe-8fec-22f854520140/scratchpad/evmcheck/main.go`
   (all 11 vectors already return `true` in geth's EVM; see SPEC §12 for per-variant revert semantics). Own go.mod (`github.com/lattice-safe/sphincsminus/evmoracle`, `replace ../`), dependency
   `github.com/ethereum/go-ethereum` (latest tag available in module cache, v1.16.x). Test loads each
   `testdata/SphincsC*Asm.bin-runtime`, ABI-encodes `verify(bytes32,bytes32,bytes32,bytes)`, runs with
   `core/vm/runtime.Execute` and asserts: reference vectors → true; Go-signed signatures (C11, C10, C9 fast;
   C7, C13 under SLOW) → true; mutated → false or revert (per SPEC §12 semantics per variant). Report gas used.
3b `cmd/sphincsminus`: `keygen [-params C13] [-material hex]`, `sign -sk hex -msg hex`, `verify -pk hex -msg hex -sig hex`,
   `vector -params C13 -msg hex` (prints the upstream ABI-encoded `(seed, root, sig)` hex so `forge` tests
   in the upstream repo can consume it). Exit codes: 0 valid / 1 invalid / 2 usage.
Gate: `cd evmoracle && go test ./...` green; CLI `vector` output for C11 message `0xdeadbeef…` equals the
upstream fixture byte-for-byte.

### Phase 4 — Hardening + docs (worker: Sonnet 5)
* Negative-test matrix completed (every signature region), constant-time root compare, zeroization.
* `go test -race`, `-count=3` stability, `staticcheck`/`go vet` clean, coverage report (target ≥ 95% core).
* README.md: what SPHINCS⁻ is, parameter table with sizes/gas, usage examples, interop story with the
  Solidity verifiers, security caveats (research construction, 2^h budget, not FIPS 205, unaudited).
* Example test `example_test.go`.
Gate: planner review (code-review pass), all suites green.

### Phase 5 — Performance (done by planner)
Replaced the `hash.Hash`-based wrapper (sync.Pool of x/crypto states, 2 allocs per hash) with an
in-repo sponge over the vendored Keccak-f[1600]; dropped the x/crypto dependency. Apple M1 Max, 10 cores:

| Benchmark   | before (Phase 2)        | after (Phase 5)       |
|-------------|-------------------------|-----------------------|
| Keygen C11  | 9.6 ms, 210 K allocs    | 7.6 ms, 577 allocs    |
| Keygen C13  | 77 ms, 1.68 M allocs    | 51 ms, 4.1 K allocs   |
| Sign C11    | 110 ms, 976 K allocs    | 64 ms, 1.7 K allocs   |
| Sign C13    | 3.10 s, 33.9 M allocs, 1.81 GB | 2.60 s, 8.7 K allocs, 247 MB |
| Verify C11  | 172 µs, 741 allocs      | 158 µs, 8 allocs      |
| Verify C13  | 158 µs, 685 allocs      | 154 µs, 8 allocs      |

## Risk register

| Risk | Mitigation |
|------|-----------|
| Bit-order mistake in LSB-first digit/index parsing | Vector test fails immediately; SPEC §7/§9 spell out shifts; use `math/big`-free uint64 window extraction with tests against a `big.Int` oracle |
| ADRS field confusion (word2/word3 overloading per type) | address_test with hand-computed bytes; the C13 Yul source is quoted in SPEC |
| Forgetting the last-FORS-tree "root hashed as leaf 0" rule | Explicit in SPEC §8; vectors catch it |
| Non-determinism (map iteration, goroutine order) | Tree build writes to indexed slices; grinding is sequential from 0 |
| C13 sign too slow in Go | Parallel leaves; reusable keccak states; Phase 5 keccak |
| go-ethereum dependency bloat | Isolated in nested module `evmoracle/` |

## Status

- [x] Phase 0 scaffold
- [x] Phase 1 primitives + verify
- [x] Phase 2 sign + keygen
- [x] Phase 3a EVM oracle
- [x] Phase 3b CLI
- [x] Phase 4 hardening + docs
- [x] Phase 5 perf (keccak sponge, zero deps)
