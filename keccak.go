package sphincsminus

import "encoding/binary"

// word is a 32-byte big-endian value. Two shapes are used throughout this
// package (SPEC §1):
//
//   - N_MASK node values: the top 16 bytes carry the significant value,
//     the low 16 bytes are zero (see maskN). All tweakable-hash outputs
//     (Th, ThPair, ThMulti) and the ADRS/PRF outputs are kept in this
//     form.
//   - Full 256-bit values: the digest returned by HMsg and the raw
//     output of WotsDigest are used in full; they are never masked.
type word [32]byte

// maskN clears the low 16 bytes of w, producing the N_MASK form used for
// every node value on the wire (SPEC §1).
func maskN(w word) word {
	var out word
	copy(out[:16], w[:16])
	return out
}

// keccakRate is the Keccak-256 sponge rate in bytes (1600 − 2·256 bits).
const keccakRate = 136

// sponge is a minimal, allocation-free Ethereum Keccak-256 (the original
// Keccak padding 0x01, not the SHA-3 0x06 domain byte). It is a concrete
// type with no interface indirection so that Go's escape analysis keeps
// callers' inputs and outputs on the stack: the hot paths (WOTS+C chain
// steps, Merkle node combination, FORS leaf generation) therefore hash
// with zero heap allocations. The permutation lives in keccakf.go.
type sponge struct {
	st  [25]uint64
	buf [keccakRate]byte
	n   int
}

// absorb feeds p into the sponge.
func (s *sponge) absorb(p []byte) {
	for len(p) > 0 {
		if s.n == 0 && len(p) >= keccakRate {
			// Fast path: XOR a whole block straight from p.
			for i := 0; i < keccakRate/8; i++ {
				s.st[i] ^= binary.LittleEndian.Uint64(p[8*i:])
			}
			keccakF1600(&s.st)
			p = p[keccakRate:]
			continue
		}
		c := copy(s.buf[s.n:], p)
		s.n += c
		p = p[c:]
		if s.n == keccakRate {
			s.permuteBuf()
		}
	}
}

// permuteBuf XORs the buffered block into the state, permutes, and empties
// the buffer.
func (s *sponge) permuteBuf() {
	for i := 0; i < keccakRate/8; i++ {
		s.st[i] ^= binary.LittleEndian.Uint64(s.buf[8*i:])
	}
	keccakF1600(&s.st)
	s.n = 0
	s.buf = [keccakRate]byte{}
}

// sum applies Keccak padding, squeezes 32 bytes into out, and leaves the
// sponge unusable (callers always use a fresh value).
func (s *sponge) sum(out *word) {
	s.buf[s.n] ^= 0x01
	s.buf[keccakRate-1] ^= 0x80
	s.permuteBuf()
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(out[8*i:], s.st[i])
	}
}

// keccakWords hashes the concatenation of in[0]..in[len(in)-1] (each a
// full 32-byte word) into out with Ethereum's Keccak-256. It is the
// primitive behind Th/ThPair/ThMulti (SPEC §5), whose inputs are always
// whole words. Zero heap allocations.
func keccakWords(out *word, in ...word) {
	var s sponge
	for i := range in {
		s.absorb(in[i][:])
	}
	s.sum(out)
}

// hashBytes hashes the concatenation of the given byte slices into out.
// It underlies the PRFs (prf.go) and the two unmasked tweakable hashes,
// HMsg and WotsDigest (thash.go), whose inputs mix ASCII domain labels,
// big-endian integers, and word values. Zero heap allocations.
func hashBytes(out *word, chunks ...[]byte) {
	var s sponge
	for _, c := range chunks {
		s.absorb(c)
	}
	s.sum(out)
}
