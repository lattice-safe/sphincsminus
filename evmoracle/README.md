# evmoracle

`evmoracle` is a nested Go module (`github.com/lattice-safe/sphincsminus/evmoracle`)
that runs the real, upstream-compiled Solidity SPHINCS⁻ verifiers inside
go-ethereum's EVM interpreter, and uses that as the final compatibility
oracle for this repository's Go signatures and verifier.

It exists as a *separate* module, with its own `go.mod` and a
`replace github.com/lattice-safe/sphincsminus => ../` back to the root
module, purely to keep the (large) `go-ethereum` dependency tree out of
the root library's `go.sum`. Anyone who just wants
`github.com/lattice-safe/sphincsminus` never pulls in go-ethereum.

## What it checks

* `TestReferenceVectorsOnChain` — every vector in `../testdata/vectors/*.json`
  verifies `true` on-chain (logs gas per vector).
* `TestGoSignaturesOnChain` — fresh Go-generated keys (`GenerateKey`) sign
  random messages, and both the Go `Verify` and the on-chain verifier agree
  the signatures are valid, for C11/C10/C9 always and C7/C13 under
  `SPHINCSMINUS_SLOW=1`.
* `TestMutationsOnChain` — the SPEC §12 on-chain failure semantics: a
  truncated signature reverts with `"Invalid sig length"`; a corrupted
  last-layer WOTS chain byte returns `false` on every variant (root
  mismatch); a corrupted FORS secret byte returns `false` on C13 but
  reverts on C7/C9/C10/C11 (digit-sum mismatch); a non-canonical `pkRoot`
  reverts with `"Invalid public key"`. The Go `Verify` is asserted to
  reject every one of these the same way (always `false`, never a panic).
* `TestGasTable` — logs a markdown table of gas used per variant, for
  pasting into a top-level README.

## Running

```bash
cd evmoracle
go mod tidy      # first run may need network for transitive go-ethereum deps
go vet ./...
go test ./...                     # fast subset (C11/C10/C9)
SPHINCSMINUS_SLOW=1 go test ./... # also exercises C7/C13 signing on-chain
go test -run TestGasTable -v ./...
```

## `oracle.go` API

```go
func LoadVerifier(p *sphincsminus.Params) (*Verifier, error)
func (v *Verifier) Verify(pkSeed, pkRoot, msg [32]byte, sig []byte) (valid bool, gasUsed uint64, err error)
func EncodeCall(pkSeed, pkRoot, msg [32]byte, sig []byte) []byte
```

`Verify` runs `LoadVerifier`'s bytecode against a single call to
`verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes sig)` in a
fresh in-memory EVM (`core/vm/runtime`, `params.AllDevChainProtocolChanges`).
A Solidity `revert` — with or without an `Error(string)` reason — is
reported as a non-nil `error` rather than `valid=false`; callers that want
SPEC §12's "any failure ⇒ reject" semantics should treat
`valid == false || err != nil` as rejection. `EncodeCall` is exported so
the CLI (Phase 3b) can print the same call data upstream `forge` tests
consume.

## Where the bytecode comes from

`testdata/SphincsC{7,9,10,11,13}Asm.bin-runtime` are the **runtime**
(deployed) bytecode of the upstream Solidity verifiers at
[`nconsigny/SPHINCS-`](https://github.com/nconsigny/SPHINCS-)
(`src/keccak/SPHINCS-C{7,9,10,11,13}Asm.sol`), produced with:

```bash
forge build --use 0.8.28 --via-ir --optimize --optimizer-runs 200
```

and then extracting each contract's `deployedBytecode.object` from the
Foundry build artifact JSON (hex, no `0x` prefix, no trailing newline) into
the corresponding `.bin-runtime` file. These are byte-for-byte what
`forge` would deploy on-chain, so a `true`/`false`/revert from this
package's `Verify` is exactly what an on-chain call would return.
