# Security Policy

## Supported versions

`sphincsminus` is pre-1.0 (see [`docs/RELEASING.md`](docs/RELEASING.md) for
the versioning policy). Only the **latest published minor version** is
supported with security fixes; there are no LTS branches. Upgrade before
reporting an issue against an older tag.

## Reporting a vulnerability

Please **do not open a public GitHub issue** for a suspected
vulnerability. Instead, use one of:

1. **GitHub private vulnerability reporting** (preferred): open a report
   at <https://github.com/lattice-safe/sphincsminus/security/advisories/new>.
   This keeps the discussion private until a fix is ready and lets you
   coordinate a CVE/advisory if warranted.
2. **Email**: suleyman.kardas@batman.edu.tr (maintainer's address) if you
   cannot use GitHub's reporting flow. Please include enough detail to
   reproduce the issue (parameter set, inputs, and, ideally, a failing
   test).

You should get an acknowledgement within a few days. This is a small,
unfunded research project maintained on a best-effort basis — please be
patient, and feel free to follow up if you haven't heard back after a
week.

## Disclosure timeline

* We aim to acknowledge a report within **7 days**.
* We aim to have a fix, mitigation, or public response within **90 days**
  of acknowledgement, and will keep the reporter updated on progress.
* We will credit the reporter (unless they ask not to be) in the
  `CHANGELOG.md` entry and any advisory once a fix ships.
* Coordinated disclosure is welcome: tell us if you have your own
  disclosure deadline and we'll do our best to meet it.

## Scope

**In scope** — please report:

* Signature forgery, or any way to produce a `(pkSeed, pkRoot, msg, sig)`
  tuple that this package's `Verify` accepts but that shouldn't be valid
  under the documented security model.
* Any divergence between this package's `Sign`/`Verify` and the upstream
  Solidity verifiers at [`nconsigny/SPHINCS-`](https://github.com/nconsigny/SPHINCS-)
  (`evmoracle/` exists specifically to catch this class of bug — a case
  it misses is a vulnerability in its own right).
* Panics, infinite loops, or excessive resource consumption triggered by
  untrusted input to `Verify`, `ParsePublicKey`, `ParsePrivateKey`, or the
  CLI's `verify`/`vector` commands — `Verify` in particular must never
  panic on adversarial input.
* Key-material leaks: secret data (`skSeed`, WOTS+C/FORS+C secrets) ending
  up somewhere it shouldn't — logs, error messages, timing/cache
  side-channels in code paths that handle secrets, or `Zeroize` failing
  to clear what it claims to.
* Non-deterministic signing (the same key and message producing different
  signatures across runs), which would undermine the determinism this
  package documents and tests against.

**Out of scope**:

* The cryptographic design of SPHINCS⁻ itself (WOTS+C's digit-sum grind,
  FORS+C's forced-zero last tree, parameter-set choices). That design
  lives upstream at [`nconsigny/SPHINCS-`](https://github.com/nconsigny/SPHINCS-)
  and in the associated ethresear.ch writeup — file design-level concerns
  there, not against this Go implementation. This repository only
  reports implementation bugs that make its Go code diverge from that
  design or from the upstream verifiers.
* Denial-of-service by simply calling `Sign` a very large number of
  times, or by choosing a parameter set with a large `2^h` signing
  budget — that's a caller-side key-management concern, documented in
  `README.md`.

## A word on maturity

**This is a research-grade construction, not FIPS 205 SLH-DSA, and it has
not been independently audited.** SPHINCS⁻ deliberately trades some of
standard SLH-DSA's conservatism (an explicit WOTS checksum, full FORS
authentication paths) for smaller signatures and cheaper on-chain
verification gas. Do not use this package to protect funds or in any
safety-critical system without an independent security review
appropriate to your threat model — see the "Security" section of
`README.md` for the full caveats.
