package sphincsminus

import "encoding/binary"

// th implements Th(seed, adrs, x) = maskN(keccak256(seed‖adrs‖x)), the
// single-input tweakable hash used for WOTS+C chain steps and FORS+C
// leaves (SPEC §5).
func th(seed, adrs, x word) word {
	var out word
	keccakWords(&out, seed, adrs, x)
	return maskN(out)
}

// thPair implements ThPair(seed, adrs, l, r) = maskN(keccak256(seed‖adrs‖l‖r)),
// the two-input tweakable hash used to combine sibling nodes in the FORS+C
// and hypertree Merkle trees (SPEC §5).
func thPair(seed, adrs, l, r word) word {
	var out word
	keccakWords(&out, seed, adrs, l, r)
	return maskN(out)
}

// thMulti implements ThMulti(seed, adrs, v[0..m-1]) =
// maskN(keccak256(seed‖adrs‖v[0]‖…‖v[m-1])), used to combine the l WOTS+C
// chain tops into a WOTS+C public key and the k FORS+C tree roots into a
// FORS+C public key (SPEC §5). Unlike th/thPair this is not on the hottest
// path (it runs once per WOTS/FORS instance rather than once per chain
// step or tree node), so the small slice allocation to prepend seed/adrs
// to v is an acceptable trade for a simple, spec-literal signature.
func thMulti(seed, adrs word, v []word) word {
	var out word
	parts := make([]word, 0, 2+len(v))
	parts = append(parts, seed, adrs)
	parts = append(parts, v...)
	keccakWords(&out, parts...)
	return maskN(out)
}

// hMsg implements HMsg(seed, root, R, msg) =
// keccak256(seed‖root‖R‖msg‖0xFF*32), the (unmasked, full 256-bit) message
// digest hash (SPEC §5). Its output is parsed by field/forsIndices/
// htIndex (digest.go), not treated as a node value, so it is intentionally
// not passed through maskN.
func hMsg(seed, root, r, msg word) word {
	var out word
	var pad [32]byte
	for i := range pad {
		pad[i] = 0xFF
	}
	hashBytes(&out, seed[:], root[:], r[:], msg[:], pad[:])
	return out
}

// wotsDigest implements
// WotsDigest(seed, adrs0, m, c) = keccak256(seed‖adrs0‖m‖be32(c)),
// the (unmasked, full 256-bit) WOTS+C digit-sum-grinding digest (SPEC §5),
// where adrs0 = ADRS(layer, tree, type=0, word1=kp, word2=0, word3=0).
func wotsDigest(seed, adrs0, m word, count uint32) word {
	var out word
	var cnt [32]byte
	binary.BigEndian.PutUint32(cnt[28:32], count)
	hashBytes(&out, seed[:], adrs0[:], m[:], cnt[:])
	return out
}
