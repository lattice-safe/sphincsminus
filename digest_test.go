package sphincsminus

import (
	"crypto/rand"
	"math/big"
	"testing"
)

// fieldOracle extracts a width-bit, LSB-first field from d using
// math/big, independently of field's limb-based implementation.
func fieldOracle(d *word, lsbOffset, width uint) uint64 {
	v := new(big.Int).SetBytes(d[:]) // big-endian, matches word's layout
	v.Rsh(v, lsbOffset)
	mask := new(big.Int).Lsh(big.NewInt(1), width)
	mask.Sub(mask, big.NewInt(1))
	v.And(v, mask)
	return v.Uint64()
}

func randWord(t *testing.T) word {
	t.Helper()
	var w word
	if _, err := rand.Read(w[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return w
}

// TestFieldVsBigIntOracle fuzzes field against a math/big oracle over the
// (offset,width) combinations actually used by the five supported
// parameter sets (forsIndices, htIndex, wotsDigits), plus a battery of
// random offset/width pairs to catch limb-boundary bugs in general.
func TestFieldVsBigIntOracle(t *testing.T) {
	var offsets []struct{ offset, width uint }

	for _, p := range AllParams {
		for i := 0; i < p.K; i++ {
			offsets = append(offsets, struct{ offset, width uint }{uint(i * p.A), uint(p.A)})
		}
		offsets = append(offsets, struct{ offset, width uint }{uint(p.K * p.A), uint(p.H)})
		for i := 0; i < p.L; i++ {
			offsets = append(offsets, struct{ offset, width uint }{uint(i * p.LogW), uint(p.LogW)})
		}
	}

	for trial := 0; trial < 200; trial++ {
		d := randWord(t)
		for _, oc := range offsets {
			got := field(&d, oc.offset, oc.width)
			want := fieldOracle(&d, oc.offset, oc.width)
			if got != want {
				t.Fatalf("field(d=%x, offset=%d, width=%d) = %d, want %d", d, oc.offset, oc.width, got, want)
			}
		}
	}
}

// TestFieldGeneralRandom fuzzes field against the oracle for uniformly
// random (offset, width) pairs across the whole 256-bit range, not just
// the specific offsets the five parameter sets happen to use.
func TestFieldGeneralRandom(t *testing.T) {
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	rng := newXorshift(seed)

	for trial := 0; trial < 2000; trial++ {
		d := randWord(t)
		width := uint(rng.next()%64 + 1) // 1..64
		maxOffset := uint(256) - width
		offset := uint(rng.next()) % (maxOffset + 1)

		got := field(&d, offset, width)
		want := fieldOracle(&d, offset, width)
		if got != want {
			t.Fatalf("field(d=%x, offset=%d, width=%d) = %d, want %d", d, offset, width, got, want)
		}
	}
}

func TestFieldEdgeCases(t *testing.T) {
	var d word
	for i := range d {
		d[i] = 0xFF
	}
	// All-ones input: every field of every width should be all-ones.
	for _, width := range []uint{1, 3, 7, 8, 11, 16, 19, 24, 63, 64} {
		for _, offset := range []uint{0, 1, 7, 8, 64, 128, 192, 256 - width} {
			got := field(&d, offset, width)
			want := (uint64(1) << width) - 1
			if width == 64 {
				want = ^uint64(0)
			}
			if got != want {
				t.Errorf("all-ones field(offset=%d,width=%d) = %#x, want %#x", offset, width, got, want)
			}
		}
	}

	if got := field(&d, 0, 0); got != 0 {
		t.Errorf("field with width=0 = %d, want 0", got)
	}
}

// xorshift is a tiny deterministic PRNG used only to generate
// reproducible-within-a-run pseudo-random offsets/widths for
// TestFieldGeneralRandom; it is not used anywhere outside this test.
type xorshift struct{ s uint64 }

func newXorshift(seed [8]byte) *xorshift {
	var s uint64
	for _, b := range seed {
		s = s<<8 | uint64(b)
	}
	if s == 0 {
		s = 1
	}
	return &xorshift{s: s}
}

func (x *xorshift) next() uint64 {
	x.s ^= x.s << 13
	x.s ^= x.s >> 7
	x.s ^= x.s << 17
	return x.s
}
