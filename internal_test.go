package sphincsminus

import (
	"context"
	"testing"
)

// TestFieldWidthPanics checks the internal-invariant guard in field
// (digest.go): every caller in this package passes width <= 64 (derived
// from a, h, or log_w, all far below that bound), so a width > 64 request
// indicates a bug in the caller rather than adversarial input, and field
// panics rather than silently truncating.
func TestFieldWidthPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("field(width=65) did not panic")
		}
	}()
	var d word
	field(&d, 0, 65)
}

// TestParallelChunksEdgeCases exercises parallelChunks' (merkle.go) small-n
// guards directly: n<=0 must be a no-op (the work function must never be
// called), and n smaller than runtime.GOMAXPROCS(0) must still partition
// and run correctly rather than spawning more workers than there is work
// for.
func TestParallelChunksEdgeCases(t *testing.T) {
	ctx := context.Background()
	if err := parallelChunks(ctx, 0, func(start, end int) {
		t.Fatalf("work called for n=0: [%d,%d)", start, end)
	}); err != nil {
		t.Errorf("parallelChunks(n=0) error = %v, want nil", err)
	}
	if err := parallelChunks(ctx, -1, func(start, end int) {
		t.Fatalf("work called for n=-1: [%d,%d)", start, end)
	}); err != nil {
		t.Errorf("parallelChunks(n=-1) error = %v, want nil", err)
	}

	for _, n := range []int{1, 2, 3} {
		seen := make([]bool, n)
		if err := parallelChunks(ctx, n, func(start, end int) {
			for i := start; i < end; i++ {
				seen[i] = true
			}
		}); err != nil {
			t.Errorf("n=%d: parallelChunks error = %v, want nil", n, err)
		}
		for i, ok := range seen {
			if !ok {
				t.Errorf("n=%d: index %d never visited", n, i)
			}
		}
	}
}

// TestParallelChunksCancel checks that parallelChunks returns ctx.Err()
// promptly (without calling work again) once ctx is already canceled
// before it is called, and that an already-canceled ctx is a pure no-op
// for n<=0 too.
func TestParallelChunksCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := parallelChunks(ctx, 1000, func(start, end int) {
		t.Fatalf("work called with an already-canceled ctx: [%d,%d)", start, end)
	}); err == nil {
		t.Error("parallelChunks with an already-canceled ctx returned nil error, want ctx.Err()")
	}
}

// TestWotsPkFromSigWrongLength checks that wotsPkFromSig (wots.go)
// rejects a wrong-length chain-signature slice by returning ok=false
// rather than panicking or reading out of bounds. Verify (verify.go)
// never actually passes it a wrong-length slice (it always slices exactly
// l*n bytes out of a length-checked signature), so this exercises the
// defensive check directly.
func TestWotsPkFromSigWrongLength(t *testing.T) {
	p := C11
	var pkSeed, msg word
	for _, badLen := range []int{0, 1, p.L*p.N - 1, p.L*p.N + 1} {
		sig := make([]byte, badLen)
		if _, ok := wotsPkFromSig(p, pkSeed, 0, 0, 0, msg, sig, 0); ok {
			t.Errorf("wotsPkFromSig(sig len=%d, want %d) ok = true, want false", badLen, p.L*p.N)
		}
	}
}
