package sphincsminus

import (
	"runtime"
	"sync"
)

// computeRoot recomputes an XMSS subtree root from a leaf value and its
// authentication path (SPEC §10, sharing the sibling-swap rule spelled
// out in SPEC §8):
//
//	treeAdrs(layer, tree, hh, i) = ADRS(layer, tree, TREE, 0, hh, i)
//	node(hh, i) = ThPair(pkSeed, treeAdrs(layer, tree, hh, i), node(hh-1, 2i), node(hh-1, 2i+1))
//
// auth must be exactly sh*n bytes (sh = Params.SubtreeHeight()), height 0
// (the leaf's sibling) first. leafIdx is the leaf's index within the
// subtree, in [0, 2^sh). computeRoot never panics: a wrong-length auth
// slice makes it read from (and return based on) a zeroed word instead of
// indexing out of range; verify.go is responsible for validating auth's
// length before calling, as it does for every other signature region.
func computeRoot(p *Params, pkSeed word, layer uint32, tree uint64, leaf word, leafIdx uint32, auth []byte) word {
	sh := p.SubtreeHeight()
	node := leaf
	idx := leafIdx
	for hh := 1; hh <= sh; hh++ {
		var sib word
		off := (hh - 1) * p.N
		if off+p.N <= len(auth) {
			copy(sib[:p.N], auth[off:off+p.N])
		}

		parent := idx >> 1
		adrs := newAdrs(layer, tree, adrsTree, 0, uint32(hh), parent)
		if idx&1 == 0 {
			node = thPair(pkSeed, adrs, node, sib)
		} else {
			node = thPair(pkSeed, adrs, sib, node)
		}
		idx = parent
	}
	return node
}

// parallelChunks splits [0, n) into up to runtime.GOMAXPROCS(0) contiguous,
// non-overlapping index ranges and calls work(start, end) for each range
// on its own goroutine, waiting for all of them to finish before
// returning. Each worker only ever touches its own [start, end) slice of
// the caller's preallocated output, so the result is deterministic
// regardless of goroutine scheduling: which worker computes a given
// index never changes, only when.
func parallelChunks(n int, work func(start, end int)) {
	if n <= 0 {
		return
	}
	workers := runtime.GOMAXPROCS(0)
	if workers > n {
		workers = n
	}
	if workers < 1 {
		workers = 1
	}
	chunk := (n + workers - 1) / workers

	var wg sync.WaitGroup
	for start := 0; start < n; start += chunk {
		end := start + chunk
		if end > n {
			end = n
		}
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			work(start, end)
		}(start, end)
	}
	wg.Wait()
}

// buildSubtree builds an XMSS subtree of height sh = Params.SubtreeHeight()
// at (layer, tree) (SPEC §10). The leaves (levels[0]) are the WOTS+C
// public keys for keypairs kp = 0..2^sh-1, computed in parallel over
// runtime.GOMAXPROCS(0) workers via wotsPkOnly (which discards the WOTS
// secret chains as soon as each leaf's public key is derived — the full
// set of 2^sh * l secrets is never held in memory at once). Levels above
// the leaves are combined pairwise with TREE-typed ADRS per SPEC §10; the
// result is levels[0..sh], with levels[sh] holding exactly the root
// (length 1).
func buildSubtree(p *Params, pkSeed, skSeed word, layer uint32, tree uint64) (levels [][]word) {
	sh := p.SubtreeHeight()
	numLeaves := 1 << uint(sh)

	leaves := make([]word, numLeaves)
	parallelChunks(numLeaves, func(start, end int) {
		for kp := start; kp < end; kp++ {
			leaves[kp] = wotsPkOnly(p, pkSeed, skSeed, layer, tree, uint32(kp))
		}
	})

	levels = make([][]word, sh+1)
	levels[0] = leaves
	cur := leaves
	for hh := 1; hh <= sh; hh++ {
		next := make([]word, len(cur)/2)
		for i := range next {
			adrs := newAdrs(layer, tree, adrsTree, 0, uint32(hh), uint32(i))
			next[i] = thPair(pkSeed, adrs, cur[2*i], cur[2*i+1])
		}
		levels[hh] = next
		cur = next
	}
	return levels
}

// subtreeRoot builds the subtree at (layer, tree) and returns just its
// root (levels[sh][0]), for callers (keys.go) that don't need the
// intermediate levels or an authentication path.
func subtreeRoot(p *Params, pkSeed, skSeed word, layer uint32, tree uint64) word {
	levels := buildSubtree(p, pkSeed, skSeed, layer, tree)
	return levels[len(levels)-1][0]
}

// authPath extracts the authentication path for leafIdx from a tree's
// levels (as returned by buildSubtree or buildForsTree): the sibling of
// the node on the path from the leaf to the root, at each height,
// starting at height 0 (the leaf's own sibling) — matching the wire
// order used by both the hypertree's XMSS auth paths and FORS+C's
// authentication paths (SPEC §8, §10, §11). It is shared between the two
// tree shapes because their level arrays have the same shape: levels[0]
// is the leaves, levels[len(levels)-1] is the single root.
func authPath(levels [][]word, leafIdx int) []word {
	height := len(levels) - 1
	auth := make([]word, height)
	idx := leafIdx
	for hh := 0; hh < height; hh++ {
		auth[hh] = levels[hh][idx^1]
		idx >>= 1
	}
	return auth
}
