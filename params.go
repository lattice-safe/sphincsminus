package sphincsminus

import "fmt"

// Params holds one SPHINCS⁻ parameter set (SPEC §2). Nothing in this
// package is hard-coded to a particular set except the recommended
// default used by convenience constructors; everything else takes a
// *Params explicitly.
type Params struct {
	// Name is a short human-readable identifier, e.g. "C13".
	Name string

	// N is the hash/node output size in bytes. Always 16 for the
	// keccak C-series (128-bit security parameter).
	N int

	// H is the total hypertree height (sum of all layer heights).
	H int

	// D is the number of hypertree layers. H must be a multiple of D;
	// each layer is an XMSS subtree of height H/D.
	D int

	// A is the FORS+C tree height (bits of message digest consumed per
	// FORS tree).
	A int

	// K is the number of FORS trees.
	K int

	// W is the WOTS+C chain base (Winternitz parameter). Only w=8 is
	// currently supported.
	W int

	// LogW is log2(W). Only log_w=3 is currently supported.
	LogW int

	// L is the number of WOTS+C chains. Only l=43 is currently
	// supported (there is no WOTS checksum in WOTS+C, so L is not
	// derived from N and LogW the way it is in FIPS 205).
	L int

	// TargetSum is the WOTS+C digit-sum grinding target that replaces
	// the FIPS 205 WOTS+ checksum (SPEC §9).
	TargetSum int
}

// SubtreeHeight returns sh = H/D, the height of each XMSS subtree in the
// hypertree.
func (p *Params) SubtreeHeight() int {
	return p.H / p.D
}

// AuthStart returns the byte offset of the FORS authentication paths
// within the signature: n (for R) plus k*n (for the k FORS secrets).
func (p *Params) AuthStart() int {
	return p.N + p.K*p.N
}

// ForsAuthBytes returns the total size in bytes of the FORS
// authentication path region: (k-1) trees, each contributing an
// a-node path of n bytes per node. The forced-zero tree (SPEC §8)
// contributes no authentication path.
func (p *Params) ForsAuthBytes() int {
	return (p.K - 1) * p.A * p.N
}

// HTStart returns the byte offset of the hypertree (WOTS+C/XMSS) region
// of the signature.
func (p *Params) HTStart() int {
	return p.AuthStart() + p.ForsAuthBytes()
}

// LayerSize returns the size in bytes of one hypertree layer's signature
// material: l WOTS+C chains, a 4-byte count, and an sh-node XMSS
// authentication path.
func (p *Params) LayerSize() int {
	return p.L*p.N + 4 + p.SubtreeHeight()*p.N
}

// SigBytes returns the total signature size in bytes (SPEC §2).
func (p *Params) SigBytes() int {
	return p.HTStart() + p.D*p.LayerSize()
}

// Validate checks internal consistency of a parameter set: the
// currently-supported WOTS+C shape (w=8, log_w=3, l=43), the security
// invariant k*a+h <= 256, that h is evenly divisible into d layers, and
// that the derived signature size is self-consistent.
func (p *Params) Validate() error {
	if p == nil {
		return fmt.Errorf("%w: nil params", ErrInvalidParams)
	}
	if p.N != 16 {
		return fmt.Errorf("%w: %s: n must be 16, got %d", ErrInvalidParams, p.Name, p.N)
	}
	if p.W != 8 || p.LogW != 3 {
		return fmt.Errorf("%w: %s: only w=8 (log_w=3) is supported, got w=%d log_w=%d", ErrInvalidParams, p.Name, p.W, p.LogW)
	}
	if p.L != 43 {
		return fmt.Errorf("%w: %s: only l=43 is supported, got %d", ErrInvalidParams, p.Name, p.L)
	}
	if p.D <= 0 {
		return fmt.Errorf("%w: %s: d must be positive, got %d", ErrInvalidParams, p.Name, p.D)
	}
	if p.H%p.D != 0 {
		return fmt.Errorf("%w: %s: h=%d is not a multiple of d=%d", ErrInvalidParams, p.Name, p.H, p.D)
	}
	if p.K*p.A+p.H > 256 {
		return fmt.Errorf("%w: %s: k*a+h = %d exceeds 256", ErrInvalidParams, p.Name, p.K*p.A+p.H)
	}
	// Independent recomputation of SIG_SIZE from the SPEC §2 formula,
	// cross-checked against the composed method calls above so that a
	// future refactor of the *Params methods can't silently drift.
	n, k, a, d, l, sh := p.N, p.K, p.A, p.D, p.L, p.SubtreeHeight()
	wantAuthStart := n + k*n
	wantHTStart := wantAuthStart + (k-1)*a*n
	wantLayerSize := l*n + 4 + sh*n
	wantSigBytes := wantHTStart + d*wantLayerSize
	if wantSigBytes != p.SigBytes() {
		return fmt.Errorf("%w: %s: sig bytes formula mismatch: got %d want %d", ErrInvalidParams, p.Name, p.SigBytes(), wantSigBytes)
	}
	return nil
}

// The five keccak C-series parameter sets (SPEC §2). C13 is the
// recommended default.
var (
	C7 = &Params{
		Name: "C7", N: 16, H: 24, D: 2, A: 16, K: 8,
		W: 8, LogW: 3, L: 43, TargetSum: 151,
	}
	C9 = &Params{
		Name: "C9", N: 16, H: 20, D: 2, A: 12, K: 11,
		W: 8, LogW: 3, L: 43, TargetSum: 208,
	}
	C10 = &Params{
		Name: "C10", N: 16, H: 18, D: 2, A: 11, K: 13,
		W: 8, LogW: 3, L: 43, TargetSum: 205,
	}
	C11 = &Params{
		Name: "C11", N: 16, H: 16, D: 2, A: 11, K: 13,
		W: 8, LogW: 3, L: 43, TargetSum: 203,
	}
	C13 = &Params{
		Name: "C13", N: 16, H: 22, D: 2, A: 19, K: 7,
		W: 8, LogW: 3, L: 43, TargetSum: 208,
	}
)

// AllParams lists every supported parameter set.
var AllParams = []*Params{C7, C9, C10, C11, C13}

// ParamsByName looks up a parameter set by its Name (e.g. "C13"). The
// comparison is case-sensitive and matches the exact Name field.
func ParamsByName(name string) (*Params, bool) {
	for _, p := range AllParams {
		if p.Name == name {
			return p, true
		}
	}
	return nil, false
}
