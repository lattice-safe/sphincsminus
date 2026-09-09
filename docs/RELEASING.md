# Releasing

## Semver policy

`sphincsminus` follows [Semantic Versioning](https://semver.org/), with
the usual pre-1.0 caveat:

* **v0.x**: a **minor** version bump (`0.x` → `0.(x+1)`) may break the Go
  API. Patch bumps (`0.x.y` → `0.x.(y+1)`) are bug-fix only and should
  not break the API.
* **The wire format never changes without a new parameter-set name.**
  The byte layout of keys and signatures for an existing parameter set
  (C7, C9, C10, C11, C13 — see `docs/SPEC.md`) is fixed for the life of
  that name: it must keep verifying against the upstream Solidity
  verifiers exactly as documented. A deliberate incompatible change to a
  variant's byte layout ships as a new parameter set with a new name, not
  as a breaking change to an existing one. This holds across every
  version bump, including major ones after 1.0.
* Once the API is declared stable (v1.0.0), normal semver applies: only a
  major bump may break the Go API.

## Release checklist

1. All CI is green on the commit being released, including the jobs that
   don't run on every PR:
   * `test` matrix (all Go versions × OSes) and its Linux/1.25 `SLOW`
     step (`SPHINCSMINUS_SLOW=1 go test ./...`).
   * `evmoracle` job, both the fast and `SPHINCSMINUS_SLOW=1` variants.
   * `lint` (gofmt, staticcheck, govulncheck) and `cross-compile`.
   * If it's been a while since `fuzz` last ran on `main` (it only runs
     on the weekly schedule and on pushes to `main`, not on every PR),
     let it complete at least once against the release commit.
2. `CHANGELOG.md` is updated: move `[Unreleased]` content into a new
   `## [vX.Y.Z] - YYYY-MM-DD` section (Keep a Changelog format), and
   update the comparison links at the bottom of the file.
3. Tag the release from `main`:
   ```bash
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push --tags
   ```
4. Verify the module resolves through the Go module proxy (this is what
   `go get`/`go install` users will actually hit):
   ```bash
   go list -m github.com/lattice-safe/sphincsminus@vX.Y.Z
   ```
   If it doesn't resolve within a few minutes, check
   `https://sum.golang.org` / `https://proxy.golang.org` reachability and
   that the tag was pushed to the canonical remote
   (`github.com/lattice-safe/sphincsminus`, module path
   `github.com/lattice-safe/sphincsminus`).
5. Create the GitHub release from the pushed tag, using the matching
   `CHANGELOG.md` section as the release notes body.

## `evmoracle` versioning

`evmoracle` is a **separate Go module** (its own `go.mod`, with a
`replace github.com/lattice-safe/sphincsminus => ../` for local
development) but it is **versioned together with the rest of the
repository**: a `vX.Y.Z` tag applies to both modules at once, and there
is no independent `evmoracle/vX.Y.Z` tag scheme.

Because it's a separate module, though, `go get`/`go install` for the
root module never pulls in `evmoracle`'s go-ethereum dependency tree, and
consumers of `evmoracle` outside this repository must use a `replace`
directive pointing at the tagged root module (or a local checkout) the
same way this repo's own `evmoracle/go.mod` does — Go's module system
does not automatically resolve a nested module's "parent" import path
from a git tag.
