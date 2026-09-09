package sphincsminus

import (
	"crypto/subtle"
	"encoding/binary"
)

// Verify checks a SPHINCS⁻ signature: parameter set p, top-aligned
// 16-byte pkSeed/pkRoot, a 32-byte message, and signature bytes sig laid
// out per SPEC §11. It mirrors the Solidity verifiers' control flow
// (SPEC §11/§12) and returns false — never panics — on any malformed or
// invalid input: a nil or structurally invalid p (see Params.Validate;
// this is what makes every internal index/shift below safe even for a
// hand-built or corrupted Params, since all of Params' fields are
// exported and a caller can always construct one directly), wrong
// lengths, a forced-zero violation, a digit-sum mismatch at any
// hypertree layer, or a final root mismatch. The root comparison is
// constant-time.
func Verify(p *Params, pkSeed, pkRoot [16]byte, msg, sig []byte) bool {
	if err := p.Validate(); err != nil {
		return false
	}
	if len(msg) != 32 {
		return false
	}
	if len(sig) != p.SigBytes() {
		return false
	}

	var seedW, rootW, msgW word
	copy(seedW[:16], pkSeed[:])
	copy(rootW[:16], pkRoot[:])
	copy(msgW[:], msg)

	var r word
	copy(r[:16], sig[0:16])

	digest := hMsg(seedW, rootW, r, msgW)

	fi := forsIndices(&digest, p)
	if fi[p.K-1] != 0 {
		return false
	}
	htIdx := htIndex(&digest, p)

	cur := forsPkFromSig(p, seedW, &digest, htIdx, sig)

	sh := p.SubtreeHeight()
	shMask := uint32(1)<<uint(sh) - 1
	idxTree := uint64(htIdx)

	htStart := p.HTStart()
	layerSize := p.LayerSize()
	l := p.L
	n := p.N

	for layer := 0; layer < p.D; layer++ {
		idxLeaf := uint32(idxTree) & shMask
		idxTree >>= uint(sh)

		base := htStart + layer*layerSize
		wotsSig := sig[base : base+l*n]

		countOff := base + l*n
		count := binary.BigEndian.Uint32(sig[countOff : countOff+4])

		authOff := countOff + 4
		auth := sig[authOff : authOff+sh*n]

		wotsPk, ok := wotsPkFromSig(p, seedW, uint32(layer), idxTree, idxLeaf, cur, wotsSig, count)
		if !ok {
			return false
		}

		cur = computeRoot(p, seedW, uint32(layer), idxTree, wotsPk, idxLeaf, auth)
	}

	return subtle.ConstantTimeCompare(cur[:16], rootW[:16]) == 1
}
