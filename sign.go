package sphincsminus

import (
	"encoding/binary"
	"fmt"
)

// subtreeCache holds a precomputed XMSS subtree (buildSubtree's levels)
// for one fixed (layer, tree) pair, so that repeated signing under the
// same key doesn't rebuild it every time. In practice the only subtree
// worth caching is the top layer (layer = d-1, tree = 0): SPEC §10 notes
// that idxTree after the last shift is always 0 (k*a+h bits are consumed
// and h = d*sh), so that subtree is the same for every message under a
// given key. Signer (keys.go) is the only place that constructs one.
type subtreeCache struct {
	layer  uint32
	tree   uint64
	levels [][]word
}

// signInternal implements SPHINCS⁻ signing end to end (SPEC §7, §8, §9,
// §10, packed per §11):
//
//  1. grind R (and, with it, the message digest) until the FORS+C
//     forced-zero condition holds (grindR, prf.go);
//  2. sign the k FORS+C trees for that digest's per-message leaf
//     (forsSign, fors.go), producing the FORS public key;
//  3. walk the d hypertree layers bottom-up, WOTS+C-signing the running
//     root at each layer's keypair and revealing that layer's XMSS
//     authentication path (wotsKeygen/wotsSign, wots.go;
//     buildSubtree/authPath, merkle.go), until the final root is
//     produced.
//
// cache, if non-nil, must be a subtreeCache for (layer=d-1, tree=0)
// built with the same (pkSeed, skSeed) as the rest of the call; it lets
// Signer (keys.go) skip rebuilding that top-layer subtree on every call.
// It is only ever consulted for the one (layer, tree) pair it was built
// for — signInternal falls back to building every other layer's subtree
// itself.
//
// Before returning, the freshly built signature is checked with Verify
// against (pkSeed, pkRoot, msg); this mirrors a defensive check the
// reference signer also performs and turns any internal inconsistency
// into an error rather than a silently-wrong signature.
func signInternal(p *Params, pkSeed, pkRoot, skSeed word, msg [32]byte, cache *subtreeCache) ([]byte, error) {
	var msgW word
	copy(msgW[:], msg[:])

	r, digest, err := grindR(p, pkSeed, pkRoot, skSeed, msgW)
	if err != nil {
		return nil, err
	}
	htIdx := htIndex(&digest, p)

	secrets, auths, forsPk := forsSign(p, pkSeed, skSeed, &digest, htIdx)

	sig := make([]byte, p.SigBytes())
	n := p.N

	copy(sig[0:n], r[:n])

	secretsBase := p.N // FORS_START = n (SPEC §2/§11)
	for t := 0; t < p.K; t++ {
		off := secretsBase + t*n
		copy(sig[off:off+n], secrets[t][:n])
	}

	authBase := p.AuthStart()
	a := p.A
	for t := 0; t < p.K-1; t++ {
		off := authBase + t*a*n
		for hh := 0; hh < a; hh++ {
			copy(sig[off+hh*n:off+hh*n+n], auths[t][hh][:n])
		}
	}

	sh := p.SubtreeHeight()
	shMask := uint32(1)<<uint(sh) - 1
	idxTree := uint64(htIdx)
	cur := forsPk

	htStart := p.HTStart()
	layerSize := p.LayerSize()
	l := p.L

	for layer := 0; layer < p.D; layer++ {
		idxLeaf := uint32(idxTree) & shMask
		idxTree >>= uint(sh)

		var levels [][]word
		if cache != nil && uint32(layer) == cache.layer && idxTree == cache.tree {
			levels = cache.levels
		} else {
			levels = buildSubtree(p, pkSeed, skSeed, uint32(layer), idxTree)
		}

		// The signing leaf's own WOTS+C secret chains are cheap to
		// recompute on their own (l=43 PRF calls plus up to l*(w-1)
		// chain steps) — far cheaper than retaining all 2^sh leaves'
		// secrets from the parallel leaf pass above, which only ever
		// computed public keys (wotsPkOnly, merkle.go/wots.go).
		sks, _ := wotsKeygen(p, pkSeed, skSeed, uint32(layer), idxTree, idxLeaf)
		wotsSig, count := wotsSign(p, pkSeed, sks, uint32(layer), idxTree, idxLeaf, cur)

		base := htStart + layer*layerSize
		for i := 0; i < l; i++ {
			copy(sig[base+i*n:base+i*n+n], wotsSig[i][:n])
		}

		countOff := base + l*n
		binary.BigEndian.PutUint32(sig[countOff:countOff+4], count)

		authOff := countOff + 4
		auth := authPath(levels, int(idxLeaf))
		for hh := 0; hh < sh; hh++ {
			copy(sig[authOff+hh*n:authOff+hh*n+n], auth[hh][:n])
		}

		cur = levels[len(levels)-1][0]
	}

	var pkSeed16, pkRoot16 [16]byte
	copy(pkSeed16[:], pkSeed[:16])
	copy(pkRoot16[:], pkRoot[:16])
	if !Verify(p, pkSeed16, pkRoot16, msg[:], sig) {
		return nil, fmt.Errorf("sphincsminus: internal error: freshly produced signature failed self-verification")
	}

	return sig, nil
}
