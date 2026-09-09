package sphincsminus

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"testing"
)

// Known-answer tests for Ethereum Keccak-256 (original Keccak padding, not
// SHA3-256). Values are the widely published reference digests.
func TestKeccak256KAT(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},
		{"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"},
		{"verify(bytes32,bytes32,bytes32,bytes)", ""}, // selector checked below
	}
	for _, c := range cases {
		var out word
		hashBytes(&out, []byte(c.in))
		if c.want != "" && hex.EncodeToString(out[:]) != c.want {
			t.Errorf("keccak256(%q) = %x, want %s", c.in, out, c.want)
		}
	}
	// The Solidity verifier's function selector, independently known from
	// the upstream repo / evmoracle: 0x2bf6eda8.
	var sel word
	hashBytes(&sel, []byte("verify(bytes32,bytes32,bytes32,bytes)"))
	if hex.EncodeToString(sel[:4]) != "2bf6eda8" {
		t.Errorf("selector = %x, want 2bf6eda8", sel[:4])
	}
}

// TestKeccakChunkingInvariance checks that the sponge gives the same digest
// regardless of how the input is split into absorb calls, across all
// lengths that straddle the 136-byte rate boundary (single block, exactly
// one block, multi-block, and the 160-byte HMsg shape).
func TestKeccakChunkingInvariance(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	for n := 0; n <= 300; n++ {
		in := make([]byte, n)
		r.Read(in)
		var whole word
		hashBytes(&whole, in)
		for _, cut := range []int{1, 31, 32, 64, 135, 136, 137} {
			if cut > n {
				continue
			}
			var split word
			hashBytes(&split, in[:cut], in[cut:])
			if !bytes.Equal(whole[:], split[:]) {
				t.Fatalf("len %d cut %d: chunked digest differs", n, cut)
			}
		}
		if n%32 == 0 && n > 0 && n <= 160 {
			ws := make([]word, n/32)
			for i := range ws {
				copy(ws[i][:], in[32*i:])
			}
			var viaWords word
			keccakWords(&viaWords, ws...)
			if !bytes.Equal(whole[:], viaWords[:]) {
				t.Fatalf("len %d: keccakWords differs from hashBytes", n)
			}
		}
	}
}
