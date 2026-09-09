package sphincsminus

import (
	"context"
	"encoding/binary"
)

// wotsSecret implements
// wotsSecret(skSeed, layer, tree, kp, chain) =
//
//	maskN(keccak256(skSeed‖"wots"‖be4(layer)‖be32(tree)‖be4(kp)‖be4(chain)))
//
// (SPEC §6). skSeed is the full 32-byte signer secret; the "wots" label is
// four ASCII bytes with no terminator.
func wotsSecret(skSeed word, layer uint32, tree uint64, kp, chain uint32) word {
	var out word
	var layerB, kpB, chainB [4]byte
	binary.BigEndian.PutUint32(layerB[:], layer)
	binary.BigEndian.PutUint32(kpB[:], kp)
	binary.BigEndian.PutUint32(chainB[:], chain)
	var treeB [32]byte
	binary.BigEndian.PutUint64(treeB[24:32], tree)
	hashBytes(&out, skSeed[:], []byte("wots"), layerB[:], treeB[:], kpB[:], chainB[:])
	return maskN(out)
}

// forsSecret implements
// forsSecret(skSeed, htIdx, t, j) = maskN(keccak256(skSeed‖"fors"‖be4(htIdx)‖be4(t)‖be4(j)))
// (SPEC §6).
func forsSecret(skSeed word, htIdx, t, j uint32) word {
	var out word
	var htIdxB, tB, jB [4]byte
	binary.BigEndian.PutUint32(htIdxB[:], htIdx)
	binary.BigEndian.PutUint32(tB[:], t)
	binary.BigEndian.PutUint32(jB[:], j)
	hashBytes(&out, skSeed[:], []byte("fors"), htIdxB[:], tB[:], jB[:])
	return maskN(out)
}

// grindRCandidate implements the single-nonce candidate function
// R(skSeed, msg, nonce) = maskN(keccak256(skSeed‖"R_grind"‖msg‖be32(nonce)))
// (SPEC §6). The grinding loop that searches nonce = 0,1,2,… for one that
// produces a valid forced-zero, digit-sum-satisfying signature is signer
// logic added in Phase 2; this is only the per-nonce hash.
func grindRCandidate(skSeed word, msg word, nonce uint64) word {
	var out word
	var nonceB [32]byte
	binary.BigEndian.PutUint64(nonceB[24:32], nonce)
	hashBytes(&out, skSeed[:], []byte("R_grind"), msg[:], nonceB[:])
	return maskN(out)
}

// grindR implements the R-grinding loop that makes signing deterministic
// while satisfying the FORS+C forced-zero rule (SPEC §7): find the
// smallest nonce >= 0 such that
//
//	r      = grindRCandidate(skSeed, msg, nonce)
//	digest = hMsg(pkSeed, pkRoot, r, msg)
//	forsIdx[k-1] = (digest >> (k*a)-bit... i.e. bits [(k-1)*a, k*a)) == 0
//
// The loop is intentionally sequential starting at nonce=0 (never
// parallel), so that signing the same (key, msg) always finds the same
// nonce and therefore produces byte-identical signatures. The last FORS
// index is read directly via field() rather than through
// forsIndices(&digest, p) (which would allocate a fresh []uint32 of
// length k on every one of the ~2^a expected attempts); this is the one
// hot loop in the whole signer that isn't leaf generation, so avoiding an
// allocation per iteration matters here.
//
// err is non-nil either because nonce exhausts the full uint32 space
// without a hit (ErrGrindExhausted, which does not happen in practice:
// the expected number of attempts is 2^a, i.e. at most 2^19 for the
// parameter sets in this package, many orders of magnitude below 2^32),
// or because ctx was canceled: ctx.Err() is checked every
// grindCheckInterval nonces (never per hash), and on cancellation grindR
// returns that error directly (distinguishable from ErrGrindExhausted by
// the caller via a direct equality check, since ErrGrindExhausted is
// never wrapped here).
func grindR(ctx context.Context, p *Params, pkSeed, pkRoot, skSeed, msg word) (r, digest word, err error) {
	lastIdxOffset := uint(p.K-1) * uint(p.A)
	width := uint(p.A)
	for nonce := uint64(0); nonce <= uint64(^uint32(0)); nonce++ {
		if nonce%grindCheckInterval == 0 {
			if err := ctx.Err(); err != nil {
				return word{}, word{}, err
			}
		}
		cand := grindRCandidate(skSeed, msg, nonce)
		d := hMsg(pkSeed, pkRoot, cand, msg)
		if field(&d, lastIdxOffset, width) == 0 {
			return cand, d, nil
		}
	}
	return word{}, word{}, ErrGrindExhausted
}

// deriveReferenceSeeds implements the reference-compatible key derivation
// used for interop with the upstream Rust/Python signers and their test
// vectors (SPEC §3.2, matching signer.py derive_keys / signer-c13 keygen):
//
//	entropy = keccak256("sphincs_signer_v1" ‖ material32)
//	pkSeed  = maskN(keccak256("pk_seed" ‖ entropy))
//	skSeed  = keccak256("sk_seed" ‖ entropy)
//
// It is NOT the random key generation path (SPEC §3.1); it exists purely
// for cross-validation against reference vectors.
func deriveReferenceSeeds(material [32]byte) (pkSeed, skSeed word) {
	var entropy word
	hashBytes(&entropy, []byte("sphincs_signer_v1"), material[:])
	// Best-effort zeroization (SPEC §13): entropy is passed by value into
	// seedsFromEntropy below, so scrubbing this local copy afterwards
	// doesn't disturb that call; it just avoids leaving the intermediate
	// entropy value sitting in this frame's stack slot any longer than
	// necessary.
	defer func() { entropy = word{} }()
	return seedsFromEntropy(entropy)
}

// seedsFromEntropy implements the second half of SPEC §3.2 directly on an
// already-computed entropy value:
//
//	pkSeed = maskN(keccak256("pk_seed" ‖ entropy))
//	skSeed = keccak256("sk_seed" ‖ entropy)
//
// It is split out from deriveReferenceSeeds because the SPEC §3.2 KAT
// (from signer-wasm/tests/cross_validate.rs) feeds entropy = 0x42*32
// directly, without the "sphincs_signer_v1"‖material wrapping step that
// deriveReferenceSeeds performs.
func seedsFromEntropy(entropy word) (pkSeed, skSeed word) {
	var pk, sk word
	hashBytes(&pk, []byte("pk_seed"), entropy[:])
	hashBytes(&sk, []byte("sk_seed"), entropy[:])
	return maskN(pk), sk
}
