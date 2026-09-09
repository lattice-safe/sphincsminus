package sphincsminus

import "testing"

// BenchmarkTh and BenchmarkThPair report the allocation behaviour of the
// hottest hashing paths (WOTS+C chain steps and Merkle node combination):
// run with -benchmem to see allocs/op directly, e.g.
//
//	go test -bench 'BenchmarkTh$|BenchmarkThPair$' -benchmem .
func BenchmarkTh(b *testing.B) {
	var seed, adrs, x word
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		x = th(seed, adrs, x)
	}
}

func BenchmarkThPair(b *testing.B) {
	var seed, adrs, l, r word
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		l = thPair(seed, adrs, l, r)
	}
}

// TestThAllocsPerRun and TestThPairAllocsPerRun pin the hottest
// tweakable-hash calls (WOTS+C chain steps and Merkle node combination) at
// zero heap allocations. keccak.go uses a concrete sponge type rather than
// the hash.Hash interface precisely so that escape analysis can keep the
// inputs and output on the stack; a regression here shows up as a large
// GC cost in signing (C13 signs perform ~10^7 hashes).
func TestThAllocsPerRun(t *testing.T) {
	var seed, adrs, x word
	allocs := testing.AllocsPerRun(1000, func() {
		x = th(seed, adrs, x)
	})
	if allocs != 0 {
		t.Errorf("th allocates %.2f times per call, want 0", allocs)
	}
}

func TestThPairAllocsPerRun(t *testing.T) {
	var seed, adrs, l, r word
	allocs := testing.AllocsPerRun(1000, func() {
		l = thPair(seed, adrs, l, r)
	})
	if allocs != 0 {
		t.Errorf("thPair allocates %.2f times per call, want 0", allocs)
	}
}
