// Package sphincsminus implements SPHINCS⁻ ("SPHINCS minus"), an
// EVM-oriented stateless hash-based signature scheme derived from SPHINCS+
// (FIPS 205) and tailored for cheap on-chain verification with Ethereum's
// keccak256. It combines WOTS+C (a digit-sum-grinding variant of WOTS+ with
// no explicit checksum digits) and FORS+C (a forced-zero variant of FORS
// that lets the last FORS tree's authentication path be omitted) with the
// FIPS 205 §4.2 uncompressed 32-byte ADRS layout.
//
// This package targets the keccak C-series parameter sets (C7, C9, C10,
// C11, C13) whose signatures are byte-compatible with, and independently
// verifiable by, the Solidity verifiers published at
// https://github.com/nconsigny/SPHINCS-. See docs/SPEC.md in this module
// for the byte-level specification these files implement; that document,
// not this one, is the authority in case of any discrepancy.
//
// # Research-grade construction
//
// SPHINCS⁻ is NOT FIPS 205 SLH-DSA and has NOT been independently audited.
// It is a research-grade construction built for cheap EVM verification,
// trading some conservatism of the standardized scheme (e.g. the WOTS+C
// digit-sum grind replacing an explicit checksum, and the FORS+C
// forced-zero rule) for smaller signatures and lower gas cost. Each key
// has a bounded signing budget of 2^h signatures (2^22 for the recommended
// C13 parameter set) before the security guarantees no longer hold. Do not
// use this package to protect value or safety-critical systems without an
// independent security review appropriate to your threat model.
//
// # Phase status
//
// Phases 1 and 2 are complete: parameter sets, tweakable hashes, PRFs,
// digest/index parsing, ADRS construction, both the verify half (Verify,
// PublicKey.Verify) and the signing half (GenerateKey,
// NewPrivateKeyFromSeeds, DeriveKeyReference, PrivateKey.Sign, Signer) of
// WOTS+C, FORS+C, and the hypertree. Signing is deterministic and its
// output is byte-compatible with the reference Rust/Python signers (see
// testdata/vectors/*.json). Not yet implemented: the EVM oracle and CLI
// (Phase 3) and further hardening/docs (Phase 4); see docs/PLAN.md.
package sphincsminus

import "errors"

// Sentinel errors returned by the parsing and validation helpers in this
// package. Verify itself never returns an error; it returns a plain bool
// and is documented to never panic, even on adversarial input.
var (
	// ErrInvalidParams is returned when a *Params value fails Validate.
	ErrInvalidParams = errors.New("sphincsminus: invalid parameter set")

	// ErrInvalidPublicKey is returned when public key bytes are the wrong
	// length or otherwise malformed.
	ErrInvalidPublicKey = errors.New("sphincsminus: invalid public key encoding")

	// ErrInvalidPrivateKey is returned when private key bytes are the
	// wrong length or otherwise malformed.
	ErrInvalidPrivateKey = errors.New("sphincsminus: invalid private key encoding")

	// ErrInvalidSignature is returned by helpers that parse signature
	// bytes into a structured form (as opposed to Verify, which reports
	// invalidity by returning false).
	ErrInvalidSignature = errors.New("sphincsminus: invalid signature encoding")

	// ErrInvalidMessageLength is returned by Sign when the message is not
	// exactly 32 bytes (SPEC §1: the message is always an EVM hash).
	ErrInvalidMessageLength = errors.New("sphincsminus: message must be exactly 32 bytes")

	// ErrGrindExhausted is returned by the internal R-grinding and
	// WOTS+C count-grinding loops if they exhaust the full uint32 nonce
	// space without finding a valid candidate. This is not expected to
	// happen for any of the supported parameter sets (the expected
	// number of grinding attempts is many orders of magnitude below
	// 2^32) and would indicate a serious bug elsewhere (e.g. a broken
	// PRF) rather than ordinary bad luck.
	ErrGrindExhausted = errors.New("sphincsminus: grinding loop exhausted the uint32 nonce space")
)
