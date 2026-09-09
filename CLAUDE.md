# CLAUDE.md — sphincsminus (Go)

Pure-Go implementation of **SPHINCS⁻ (SPHINCS minus)**: EVM-oriented stateless
hash-based signatures (WOTS+C / FORS+C over keccak256, FIPS 205 uncompressed ADRS),
byte-compatible with the Solidity verifiers in https://github.com/nconsigny/SPHINCS-.

## Authority
* `docs/SPEC.md` is the byte-level spec. If code and SPEC disagree, SPEC wins;
  if SPEC and a reference vector disagree, the vector wins and SPEC must be fixed.
* `docs/PLAN.md` is the implementation plan and phase status.
* `testdata/vectors/*.json` are reference vectors from the upstream Rust/Python signers.
* `evmoracle/` is a separate Go module that runs the real Solidity verifier bytecode
  (`evmoracle/testdata/*.bin-runtime`) inside go-ethereum's EVM as the final oracle.

## Conventions
* Flat package `sphincsminus` at repo root, like the sibling `lattice-slh-dsa-go`.
* Node values are `[32]byte` words in N_MASK form (top 16 bytes value, low 16 zero).
* Parameter sets are values of `*Params`; nothing is hard-coded to C13 except defaults.
* No CGO, no assembly, no external dependencies. Keccak-256 is implemented in `keccak.go` (allocation-free sponge) over the permutation vendored in `keccakf.go` from `golang.org/x/crypto` (BSD, see `LICENSE-THIRD-PARTY`). Hot-path hashes are pinned at 0 allocs/op by tests.
* Verify must never panic on adversarial input; return `false`.
* Zero allocations in hash hot paths where practical; sign is parallelised with goroutines.

## Commands
```bash
go build ./... && go vet ./...
go test ./...                 # fast tests (C13 full sign gated behind -run/ENV, see tests)
go test -run TestVectors -v ./...
SPHINCSMINUS_SLOW=1 go test ./...   # includes full C13/C7 sign roundtrips
cd evmoracle && go test ./...       # Solidity-verifier oracle (needs network for go-ethereum on first run)
go test -bench . -benchmem ./...
```
