package sphincsminus

// chain applies the WOTS+C chaining function to x, walking `steps` hash
// steps starting at position `start` (SPEC §9):
//
//	chain(x, start, steps): for pos in start..start+steps-1: x = Th(pkSeed, adrsHash(i,pos), x); return x
//
// adrs must already carry (layer, tree, type=WOTS_HASH, word1=kp,
// word2=i); its word3 (hash_address / pos) is overwritten in place on
// each step, so callers must pass a value they don't need to reuse
// unmodified afterwards.
func chain(p *Params, pkSeed word, adrs word, x word, start, steps uint32) word {
	cur := x
	a := adrs
	end := start + steps
	for pos := start; pos < end; pos++ {
		setWord3(&a, pos)
		cur = th(pkSeed, a, cur)
	}
	return cur
}

// wotsPkFromSig recomputes a WOTS+C public key node from a signature over
// msg (SPEC §9). sig must be exactly l*n bytes (the wire chain values,
// 16 bytes each, N_MASK top-aligned). count is the digit-sum-grinding
// counter carried alongside the signature.
//
// ok is false (and wotsPk is the zero word) whenever the recomputed
// digit sum does not equal Params.TargetSum; verify.go must check ok and
// never trust wotsPk when it is false. wotsPkFromSig never panics: a
// wrong-length sig also yields ok=false.
func wotsPkFromSig(p *Params, pkSeed word, layer uint32, tree uint64, kp uint32, msg word, sig []byte, count uint32) (wotsPk word, ok bool) {
	if len(sig) != p.L*p.N {
		return word{}, false
	}

	adrs0 := newAdrs(layer, tree, adrsWotsHash, kp, 0, 0)
	d := wotsDigest(pkSeed, adrs0, msg, count)
	digits := wotsDigits(&d, p)
	if digitSum(digits) != uint32(p.TargetSum) {
		return word{}, false
	}

	pkNodes := make([]word, p.L)
	for i := 0; i < p.L; i++ {
		var x word
		copy(x[:p.N], sig[i*p.N:(i+1)*p.N])

		adrs := newAdrs(layer, tree, adrsWotsHash, kp, uint32(i), 0)
		start := uint32(digits[i])
		steps := uint32(p.W-1) - start
		pkNodes[i] = chain(p, pkSeed, adrs, x, start, steps)
	}

	adrsPk := newAdrs(layer, tree, adrsWotsPk, kp, 0, 0)
	return thMulti(pkSeed, adrsPk, pkNodes), true
}

// wotsKeygen computes the l WOTS+C secret-key chain bases and the
// resulting public key node for keypair (layer, tree, kp) (SPEC §9):
//
//	sk[i] = wotsSecret(skSeed, layer, tree, kp, i)
//	pk[i] = chain(sk[i], 0, w-1)
//	wotsPk = ThMulti(pkSeed, adrsPk, pk[0..l-1])
//
// It is the signer-side counterpart of wotsPkFromSig and is used both to
// derive one signing leaf's secret chains (sk.go calls this once per
// hypertree layer, for the single keypair being signed) and, via
// wotsPkOnly below, to generate every leaf of an XMSS subtree without
// retaining secrets that aren't needed again.
func wotsKeygen(p *Params, pkSeed, skSeed word, layer uint32, tree uint64, kp uint32) (sks []word, wotsPk word) {
	sks = make([]word, p.L)
	pkNodes := make([]word, p.L)
	for i := 0; i < p.L; i++ {
		sk := wotsSecret(skSeed, layer, tree, kp, uint32(i))
		sks[i] = sk
		adrs := newAdrs(layer, tree, adrsWotsHash, kp, uint32(i), 0)
		pkNodes[i] = chain(p, pkSeed, adrs, sk, 0, uint32(p.W-1))
	}
	adrsPk := newAdrs(layer, tree, adrsWotsPk, kp, 0, 0)
	wotsPk = thMulti(pkSeed, adrsPk, pkNodes)
	return sks, wotsPk
}

// wotsPkOnly computes just the WOTS+C public key node for keypair
// (layer, tree, kp), without retaining the l secret-key chain bases. It
// is the leaf-generation primitive used when building an XMSS subtree
// (merkle.go's buildSubtree): keeping 2^sh * l secrets in memory at once
// would be wasteful when only the single signing leaf's secrets are ever
// needed again (recomputed separately via wotsKeygen).
func wotsPkOnly(p *Params, pkSeed, skSeed word, layer uint32, tree uint64, kp uint32) word {
	pkNodes := make([]word, p.L)
	for i := 0; i < p.L; i++ {
		sk := wotsSecret(skSeed, layer, tree, kp, uint32(i))
		adrs := newAdrs(layer, tree, adrsWotsHash, kp, uint32(i), 0)
		pkNodes[i] = chain(p, pkSeed, adrs, sk, 0, uint32(p.W-1))
	}
	adrsPk := newAdrs(layer, tree, adrsWotsPk, kp, 0, 0)
	return thMulti(pkSeed, adrsPk, pkNodes)
}

// wotsFindCount implements the WOTS+C digit-sum grind (SPEC §9): find the
// smallest count >= 0 such that the base-w digits of
// WotsDigest(pkSeed, ADRS(layer,tree,0,kp,0,0), msg, count) sum to
// Params.TargetSum. The loop starts at 0 and is sequential, matching the
// verifier's own digit recomputation (wotsPkFromSig) exactly so the two
// never disagree about what "count" means. Grinding is expected to
// terminate quickly (there is no known input for which it doesn't; the
// uint32 space is exhausted only in a scenario that would already
// indicate a much deeper problem elsewhere, so this panics rather than
// threading an error through every caller for a case that cannot occur
// in practice).
func wotsFindCount(p *Params, pkSeed word, layer uint32, tree uint64, kp uint32, msg word) (count uint32, digits [43]uint8) {
	adrs0 := newAdrs(layer, tree, adrsWotsHash, kp, 0, 0)
	target := uint32(p.TargetSum)
	for c := uint32(0); ; c++ {
		d := wotsDigest(pkSeed, adrs0, msg, c)
		digs := wotsDigits(&d, p)
		if digitSum(digs) == target {
			return c, digs
		}
		if c == ^uint32(0) {
			panic("sphincsminus: wotsFindCount exhausted the uint32 count space")
		}
	}
}

// wotsSign implements WOTS+C signing (SPEC §9): grind the count via
// wotsFindCount, then reveal sig[i] = chain(sks[i], 0, digit[i]) for each
// of the l chains. sks must be the l secret-key chain bases for this
// exact (layer, tree, kp), as returned by wotsKeygen.
func wotsSign(p *Params, pkSeed word, sks []word, layer uint32, tree uint64, kp uint32, msg word) (sig []word, count uint32) {
	count, digits := wotsFindCount(p, pkSeed, layer, tree, kp, msg)
	sig = make([]word, p.L)
	for i := 0; i < p.L; i++ {
		adrs := newAdrs(layer, tree, adrsWotsHash, kp, uint32(i), 0)
		sig[i] = chain(p, pkSeed, adrs, sks[i], 0, uint32(digits[i]))
	}
	return sig, count
}
