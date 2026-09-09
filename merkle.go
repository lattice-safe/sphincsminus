package sphincsminus

import (
	"context"
	"runtime"
	"sync"
)

// grindCheckInterval is how many loop iterations (grindR, wotsFindCount)
// or work-items (parallelChunks' per-goroutine sub-batches) pass between
// ctx.Err() checks in the signing hot loops. It is deliberately coarse
// (never per-hash) so that threading ctx through these loops has no
// measurable effect on signing throughput for the common case of an
// uncancelled context.Background(), while still bounding how long a
// cancellation takes to be noticed to a small, constant amount of extra
// work (SPEC §13 / Phase 4 hardening task).
const grindCheckInterval = 4096

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
//
// Each worker's range is itself processed in sub-batches of at most
// grindCheckInterval items, with a ctx.Err() check between sub-batches
// (never per item, let alone per hash): if ctx is canceled or its
// deadline expires, every worker notices within one sub-batch and
// returns without completing its remaining range. parallelChunks always
// waits for every spawned goroutine before returning (there is no early
// return that leaves a goroutine running), so a canceled ctx can never
// leak a goroutine; it can only make the caller-supplied output slices
// partially filled, which is fine because the caller (buildSubtree/
// buildForsTree) discards them and propagates ctx.Err() instead. With an
// uncancelled ctx (context.Background()), ctx.Err() is a cheap,
// allocation-free nil check, so this sub-batching costs a small,
// constant amount of extra loop overhead and never changes which
// goroutine computes which index -- the result is still byte-identical.
func parallelChunks(ctx context.Context, n int, work func(start, end int)) error {
	if n <= 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
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
			for s := start; s < end; s += grindCheckInterval {
				e := s + grindCheckInterval
				if e > end {
					e = end
				}
				work(s, e)
				if ctx.Err() != nil {
					return
				}
			}
		}(start, end)
	}
	wg.Wait()
	return ctx.Err()
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
//
// ctx is checked once per parallelChunks sub-batch during leaf
// generation and once per level during the (sequential) level-combine
// phase above the leaves; if it is canceled, buildSubtree returns
// (nil, ctx.Err()) instead of a partially-built result. Passing
// context.Background() reproduces the unconditional, always-completes
// behaviour this function had before ctx support was added.
func buildSubtree(ctx context.Context, p *Params, pkSeed, skSeed word, layer uint32, tree uint64) (levels [][]word, err error) {
	sh := p.SubtreeHeight()
	numLeaves := 1 << uint(sh)

	leaves := make([]word, numLeaves)
	if err := parallelChunks(ctx, numLeaves, func(start, end int) {
		for kp := start; kp < end; kp++ {
			leaves[kp] = wotsPkOnly(p, pkSeed, skSeed, layer, tree, uint32(kp))
		}
	}); err != nil {
		return nil, err
	}

	levels = make([][]word, sh+1)
	levels[0] = leaves
	cur := leaves
	for hh := 1; hh <= sh; hh++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		next := make([]word, len(cur)/2)
		for i := range next {
			adrs := newAdrs(layer, tree, adrsTree, 0, uint32(hh), uint32(i))
			next[i] = thPair(pkSeed, adrs, cur[2*i], cur[2*i+1])
		}
		levels[hh] = next
		cur = next
	}
	return levels, nil
}

// subtreeRoot builds the subtree at (layer, tree) and returns just its
// root (levels[sh][0]), for callers (keys.go) that don't need the
// intermediate levels or an authentication path.
func subtreeRoot(ctx context.Context, p *Params, pkSeed, skSeed word, layer uint32, tree uint64) (word, error) {
	levels, err := buildSubtree(ctx, p, pkSeed, skSeed, layer, tree)
	if err != nil {
		return word{}, err
	}
	return levels[len(levels)-1][0], nil
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
