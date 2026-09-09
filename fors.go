package sphincsminus

import "context"

// forsPkFromSig recomputes the FORS+C public key node from a signature
// (SPEC §8). sig is the *whole* signature byte slice (the FORS secrets
// and authentication paths live at fixed offsets within it, per SPEC
// §11); the caller (verify.go) is responsible for checking
// len(sig) == Params.SigBytes() before calling this, since the offsets
// below are computed from Params alone and this function does not
// re-validate the overall length. Individual slice reads are still
// bounds-guarded so a caller mistake here degrades to zero-filled reads
// (and thus a mismatching, rejected root) rather than a panic.
//
// digest is the full HMsg output; htIdx is the hypertree leaf index
// already parsed from it (htIndex, digest.go). All FORS ADRS use
// layer=0, tree=idxTree0, word1=idxLeaf0, where idxTree0/idxLeaf0 are the
// bottom-layer tree/leaf split of htIdx (SPEC §8):
//
//	leaf(t, j)   = Th(pkSeed, leafAdrs(t, j), forsSecret(...))
//	node(t,hh,i) = ThPair(pkSeed, nodeAdrs(t, hh, i), node(t,hh-1,2i), node(t,hh-1,2i+1))
//	root(t)      = node(t, a, 0)
//
// Tree k-1 is the forced-zero tree: its wire "secret" is root(k-1)
// itself, hashed as leaf 0 of that tree with no authentication path
// (SPEC §8). The caller must independently check forsIndices(digest,p)[K-1]
// == 0 before trusting the result; forsPkFromSig itself does not enforce
// the forced-zero rule (it has no way to signal that failure other than
// through its unconditional word return).
func forsPkFromSig(p *Params, pkSeed word, digest *word, htIdx uint32, sig []byte) (forsPk word) {
	sh := uint32(p.SubtreeHeight())
	shMask := uint32(1)<<sh - 1
	idxTree0 := uint64(htIdx >> sh)
	idxLeaf0 := htIdx & shMask

	fi := forsIndices(digest, p)
	a := uint32(p.A)

	secretsBase := p.N // FORS_START = n (SPEC §2/§11)
	authBase := p.AuthStart()

	roots := make([]word, p.K)
	for t := 0; t < p.K; t++ {
		var secret word
		off := secretsBase + t*p.N
		if off+p.N <= len(sig) {
			copy(secret[:p.N], sig[off:off+p.N])
		}

		if t == p.K-1 {
			// Forced-zero tree: secret is root(k-1); hash it as leaf 0.
			leafAdrs := newAdrs(0, idxTree0, adrsForsTree, idxLeaf0, 0, uint32(t)<<a)
			roots[t] = th(pkSeed, leafAdrs, secret)
			continue
		}

		idx := fi[t]
		leafAdrs := newAdrs(0, idxTree0, adrsForsTree, idxLeaf0, 0, (uint32(t)<<a)|idx)
		node := th(pkSeed, leafAdrs, secret)

		authOff := authBase + t*p.A*p.N
		for hh := uint32(1); hh <= a; hh++ {
			var sib word
			o := authOff + int(hh-1)*p.N
			if o+p.N <= len(sig) {
				copy(sib[:p.N], sig[o:o+p.N])
			}

			parent := idx >> 1
			nodeAdrs := newAdrs(0, idxTree0, adrsForsTree, idxLeaf0, hh, (uint32(t)<<(a-hh))|parent)
			if idx&1 == 0 {
				node = thPair(pkSeed, nodeAdrs, node, sib)
			} else {
				node = thPair(pkSeed, nodeAdrs, sib, node)
			}
			idx = parent
		}
		roots[t] = node
	}

	rootsAdrs := newAdrs(0, idxTree0, adrsForsRoots, idxLeaf0, 0, 0)
	return thMulti(pkSeed, rootsAdrs, roots)
}

// buildForsTree builds the height-a Merkle tree for one FORS+C tree index
// t at hypertree leaf htIdx (SPEC §8):
//
//	leafAdrs(t, j)     = ADRS(0, idxTree0, 3, idxLeaf0, 0,  (t<<a)|j)
//	nodeAdrs(t, hh, i) = ADRS(0, idxTree0, 3, idxLeaf0, hh, (t<<(a-hh))|i)
//	leaf(t, j)         = Th(pkSeed, leafAdrs(t, j), forsSecret(skSeed, htIdx, t, j))
//	node(t,hh,i)       = ThPair(pkSeed, nodeAdrs(t, hh, i), node(t,hh-1,2i), node(t,hh-1,2i+1))
//
// Leaf generation (2^a of them: 2^19 = 524288 for C13) is parallelized
// over runtime.GOMAXPROCS(0) workers (parallelChunks, merkle.go); the a
// levels above are combined sequentially, one level at a time. Callers
// (forsSign) build one tree at a time and let it go out of scope once
// they've extracted the root/auth path they need, so peak memory is
// bounded by one tree's worth of leaves (16 MiB for C13) rather than all
// k of them at once.
//
// Each per-leaf secret is a stack-local temporary that is zeroed
// immediately after it has been hashed into the (public) leaf value
// (SPEC §13, best-effort: Go's runtime can still leave copies in
// registers or a reused stack slot, but this closes the easiest window).
// ctx is checked once per parallelChunks sub-batch during leaf
// generation and once per level during the level-combine phase; on
// cancellation buildForsTree returns (nil, ctx.Err()).
func buildForsTree(ctx context.Context, p *Params, pkSeed, skSeed word, htIdx, t uint32) (levels [][]word, err error) {
	sh := uint32(p.SubtreeHeight())
	shMask := uint32(1)<<sh - 1
	idxTree0 := uint64(htIdx >> sh)
	idxLeaf0 := htIdx & shMask
	a := uint32(p.A)
	numLeaves := 1 << uint(a)

	leaves := make([]word, numLeaves)
	if err := parallelChunks(ctx, numLeaves, func(start, end int) {
		for j := start; j < end; j++ {
			secret := forsSecret(skSeed, htIdx, t, uint32(j))
			leafAdrs := newAdrs(0, idxTree0, adrsForsTree, idxLeaf0, 0, (t<<a)|uint32(j))
			leaves[j] = th(pkSeed, leafAdrs, secret)
			secret = word{}
		}
	}); err != nil {
		return nil, err
	}

	levels = make([][]word, a+1)
	levels[0] = leaves
	cur := leaves
	for hh := uint32(1); hh <= a; hh++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		next := make([]word, len(cur)/2)
		for i := range next {
			nodeAdrs := newAdrs(0, idxTree0, adrsForsTree, idxLeaf0, hh, (t<<(a-hh))|uint32(i))
			next[i] = thPair(pkSeed, nodeAdrs, cur[2*i], cur[2*i+1])
		}
		levels[hh] = next
		cur = next
	}
	return levels, nil
}

// forsSign implements FORS+C signing (SPEC §8) for the k trees keyed by
// the per-message hypertree leaf htIdx. digest is the full HMsg output
// (its low k*a bits give the per-tree leaf indices, SPEC §7); the caller
// (sign.go) is responsible for having already checked the forced-zero
// condition (forsIndices(digest,p)[K-1] == 0) before calling this, since
// that's what grindR (prf.go) exists to guarantee.
//
// For trees t = 0..k-2, secrets[t] is forsSecret(skSeed, htIdx, t,
// forsIdx[t]) and auths[t] is that leaf's a-node authentication path.
// Tree k-1 is the forced-zero tree: secrets[k-1] is root(k-1) itself
// (revealed directly, with no authentication path — auths[k-1] is left
// nil and the caller must not emit anything for it), hashed as "leaf 0"
// of that tree when folded into forsPk, matching the verifier's
// forsPkFromSig exactly.
//
// ctx is checked once per tree (between buildForsTree calls) in addition
// to the finer-grained checks buildForsTree itself performs; on
// cancellation forsSign returns a non-nil err and the other return
// values are zero/nil and must not be used.
func forsSign(ctx context.Context, p *Params, pkSeed, skSeed word, digest *word, htIdx uint32) (secrets []word, auths [][]word, forsPk word, err error) {
	k := p.K
	a := uint32(p.A)
	sh := uint32(p.SubtreeHeight())
	shMask := uint32(1)<<sh - 1
	idxTree0 := uint64(htIdx >> sh)
	idxLeaf0 := htIdx & shMask

	fi := forsIndices(digest, p)

	secrets = make([]word, k)
	auths = make([][]word, k)
	roots := make([]word, k)

	for t := 0; t < k-1; t++ {
		if e := ctx.Err(); e != nil {
			return nil, nil, word{}, e
		}
		tt := uint32(t)
		idx := int(fi[t])

		levels, e := buildForsTree(ctx, p, pkSeed, skSeed, htIdx, tt)
		if e != nil {
			return nil, nil, word{}, e
		}
		secrets[t] = forsSecret(skSeed, htIdx, tt, uint32(idx))
		auths[t] = authPath(levels, idx)
		roots[t] = levels[a][0]
	}

	if e := ctx.Err(); e != nil {
		return nil, nil, word{}, e
	}

	// Forced-zero tree: reveal root(k-1) itself, no authentication path.
	tLast := uint32(k - 1)
	levels, e := buildForsTree(ctx, p, pkSeed, skSeed, htIdx, tLast)
	if e != nil {
		return nil, nil, word{}, e
	}
	rootKMinus1 := levels[a][0]
	secrets[k-1] = rootKMinus1

	leafAdrs := newAdrs(0, idxTree0, adrsForsTree, idxLeaf0, 0, tLast<<a)
	roots[k-1] = th(pkSeed, leafAdrs, rootKMinus1)

	rootsAdrs := newAdrs(0, idxTree0, adrsForsRoots, idxLeaf0, 0, 0)
	forsPk = thMulti(pkSeed, rootsAdrs, roots)

	return secrets, auths, forsPk, nil
}
