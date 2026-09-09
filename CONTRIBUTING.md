# Contributing

Thanks for your interest in `sphincsminus`. This is a small research
project; contributions are welcome, but please read the notes below
before sending a PR, especially if it touches the wire format.

## Dev setup

You need Go **1.22+** for the root module (`github.com/lattice-safe/sphincsminus`,
which includes `cmd/sphincsminus`), and Go **1.25+** if you also want to
work on `evmoracle` (a separate nested module — see
[`evmoracle/README.md`](evmoracle/README.md)). No other tools are
required to build or run the fast test suite; `evmoracle` needs network
access on its first `go mod tidy`/`go test` to fetch go-ethereum.

```bash
git clone https://github.com/skardas/sphincsminus
cd sphincsminus
go build ./...
go vet ./...
go test ./...
```

Or use the [`Makefile`](Makefile): `make build`, `make test`, etc. (run
`make` with no target, or read the file, for the full list).

## Test commands

These mirror what CI runs (`.github/workflows/ci.yml`):

```bash
go vet ./... && go test -race ./...            # fast, ~1 min with race
SPHINCSMINUS_SLOW=1 go test ./...              # + full C7/C13 signing, ~20 s
cd evmoracle && go test ./...                  # on-chain oracle, ~1 s
cd evmoracle && SPHINCSMINUS_SLOW=1 go test ./... # + C7/C13 on-chain, ~10 s
go test -run xxx -fuzz FuzzVerify -fuzztime 30s .
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

Please run at least `go vet ./... && go test -race ./...` (and, if you
touched signing, `SPHINCSMINUS_SLOW=1 go test ./...`) before opening a
PR. CI also cross-compiles for linux/amd64, linux/arm64, linux/386,
windows/amd64, darwin/arm64, and js/wasm — if you're changing anything
platform-sensitive (build tags, `unsafe`, syscalls), check those targets
build (`make cross`).

## `docs/SPEC.md` is the authority

[`docs/SPEC.md`](docs/SPEC.md) is the byte-level specification this
package implements, transcribed from the upstream reference
implementation. The rule, stated there and worth repeating:

> If code and SPEC disagree, SPEC wins; if SPEC and a reference vector
> disagree, the vector wins and SPEC must be fixed.

Concretely:

* **Any change to the wire format** (public/private key encoding,
  signature layout, ADRS construction, hashing order, address/domain
  separation) must update `docs/SPEC.md` in the same PR, and must come
  with **regenerated upstream reference vectors** proving the new format
  still round-trips through the real Solidity verifiers (or, if it's a
  deliberate incompatibility, a new parameter-set name — see
  `docs/RELEASING.md`'s semver policy: the wire format never changes
  silently under an existing name).
* A change that only affects internal representation (not the wire
  format) doesn't need new vectors, but should still pass the existing
  ones unchanged.
* If you find a place where `docs/SPEC.md` and this package's behavior
  disagree, treat it as a bug report against whichever one is wrong, and
  say so explicitly in the PR description — don't silently "fix" the
  spec to match code or vice versa without checking against the
  reference vectors/verifiers first.

## Regenerating reference vectors

Reference vectors live in `testdata/vectors/*.json` (one file per
parameter set) and are produced by the **upstream** repository,
[`nconsigny/SPHINCS-`](https://github.com/nconsigny/SPHINCS-), not by
this one — this package must match that output, not the other way
around.

* **C13**: the upstream `signer-wasm` Rust CLI.
  ```bash
  # from a checkout of nconsigny/SPHINCS-
  cd signer-wasm
  cargo run --bin signer-c13 -- keygen
  cargo run --bin signer-c13 -- sign <material-hex> <msg-hex>
  # or "sign-with" if the CLI exposes explicit key material; see that
  # repo's README for exact flags, they occasionally change.
  ```
* **C7, C9, C10, C11**: the upstream `script/signer.py`, which needs
  `pycryptodome`:
  ```bash
  pip install pycryptodome
  python3 script/signer.py <variant> <msg-hex>   # variant: c7 | c9 | c10 | c11
  ```
* **Solidity verifier bytecode** (`evmoracle/testdata/*.bin-runtime`):
  build the upstream contracts with Foundry and extract each contract's
  `deployedBytecode.object`:
  ```bash
  forge build --use 0.8.28 --via-ir --optimize --optimizer-runs 200
  # then pull deployedBytecode.object out of the build artifact JSON for
  # each SPHINCS-C{7,9,10,11,13}Asm contract into the matching
  # .bin-runtime file (hex, no "0x" prefix, no trailing newline).
  ```

After regenerating a vector, run the full suite including `evmoracle`
(`SPHINCSMINUS_SLOW=1 go test ./...` in both modules) to confirm the new
vector verifies both in this package's pure-Go `Verify` and against the
real Solidity bytecode.

## Commit style

Plain, descriptive commit messages (what changed and why); no enforced
prefix convention (no required `feat:`/`fix:` etc.), but keep the subject
line short and put detail in the body if needed. Squash noisy
work-in-progress history before opening a PR if you can.

## Sign-off / DCO

No DCO sign-off or CLA is required to contribute.

## Reporting security issues

Please don't open a public issue for a suspected vulnerability — see
[`SECURITY.md`](SECURITY.md) for how to report it privately.
