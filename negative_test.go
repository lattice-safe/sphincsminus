package sphincsminus

import (
	"encoding/binary"
	"fmt"
	"testing"
)

// regionRange describes one structurally distinct, contiguous byte range
// within a signature, per SPEC §11's wire layout. end is exclusive.
type regionRange struct {
	name       string
	start, end int
}

// signatureRegions enumerates every structurally distinct region of a
// signature for parameter set p (SPEC §11): R, each of the k FORS
// secrets (including the forced-zero tree, t=k-1, which carries root(k-1)
// instead of a leaf secret but is still exactly n bytes wide), each of
// the k-1 FORS authentication paths (the forced-zero tree has none), and,
// per hypertree layer, its l WOTS+C chains, its 4-byte count field, and
// its sh-node XMSS authentication path.
func signatureRegions(p *Params) []regionRange {
	n := p.N
	var regions []regionRange
	regions = append(regions, regionRange{"R", 0, n})

	for t := 0; t < p.K; t++ {
		off := n + t*n
		regions = append(regions, regionRange{fmt.Sprintf("fors_secret[%d]", t), off, off + n})
	}

	authBase := p.AuthStart()
	a := p.A
	for t := 0; t < p.K-1; t++ {
		off := authBase + t*a*n
		regions = append(regions, regionRange{fmt.Sprintf("fors_auth[%d]", t), off, off + a*n})
	}

	htStart := p.HTStart()
	layerSize := p.LayerSize()
	sh := p.SubtreeHeight()
	l := p.L
	for layer := 0; layer < p.D; layer++ {
		base := htStart + layer*layerSize
		regions = append(regions, regionRange{fmt.Sprintf("wots_chains[layer=%d]", layer), base, base + l*n})
		countOff := base + l*n
		regions = append(regions, regionRange{fmt.Sprintf("count[layer=%d]", layer), countOff, countOff + 4})
		authOff := countOff + 4
		regions = append(regions, regionRange{fmt.Sprintf("xmss_auth[layer=%d]", layer), authOff, authOff + sh*n})
	}
	return regions
}

// firstVectorPerVariant returns, for each testdata/vectors/*.json file,
// its Params and its first vector entry -- "for each variant's first
// vector" per the Phase 4 task brief.
func firstVectorPerVariant(t *testing.T) map[string]struct {
	p *Params
	e vectorEntry
} {
	t.Helper()
	out := map[string]struct {
		p *Params
		e vectorEntry
	}{}
	for _, vf := range loadVectorFiles(t) {
		if len(vf.Vectors) == 0 {
			t.Fatalf("variant %s has no vectors", vf.Variant)
		}
		p, ok := ParamsByName(vf.Variant)
		if !ok {
			t.Fatalf("unknown variant %q", vf.Variant)
		}
		out[vf.Variant] = struct {
			p *Params
			e vectorEntry
		}{p, vf.Vectors[0]}
	}
	return out
}

// TestNegativeMatrixRegionBoundaries implements the region-level negative
// matrix from the Phase 4 task brief: for each variant's first vector,
// for every structurally meaningful region of the signature (R, each
// FORS secret including the forced-zero one, each FORS authentication
// path, and each hypertree layer's WOTS+C chains/count/XMSS auth path),
// flipping one byte at the region's first offset and at its last offset
// must make Verify reject.
func TestNegativeMatrixRegionBoundaries(t *testing.T) {
	for variant, vp := range firstVectorPerVariant(t) {
		variant, vp := variant, vp
		t.Run(variant, func(t *testing.T) {
			p := vp.p
			msg, pkSeed, pkRoot, sig := vectorInputs(t, vp.e)

			if !Verify(p, pkSeed, pkRoot, msg, sig) {
				t.Fatalf("baseline vector does not verify; aborting")
			}
			if len(sig) != p.SigBytes() {
				t.Fatalf("vector sig length %d != Params.SigBytes() %d", len(sig), p.SigBytes())
			}

			for _, r := range signatureRegions(p) {
				if r.start < 0 || r.end > len(sig) || r.start >= r.end {
					t.Fatalf("region %s has bogus bounds [%d,%d) for sig len %d", r.name, r.start, r.end, len(sig))
				}

				startMutated := flipByte(sig, r.start)
				if Verify(p, pkSeed, pkRoot, msg, startMutated) {
					t.Errorf("flipping first byte of region %s (offset %d) still verifies", r.name, r.start)
				}

				endOff := r.end - 1
				endMutated := flipByte(sig, endOff)
				if Verify(p, pkSeed, pkRoot, msg, endMutated) {
					t.Errorf("flipping last byte of region %s (offset %d) still verifies", r.name, endOff)
				}
			}
		})
	}
}

// TestNegativeCountForcedToMax sets each hypertree layer's count field to
// 0xFFFFFFFF (SPEC §9/§11): per the task brief, a different count value
// that happens to preserve the WOTS+C digit sum is astronomically
// unlikely, so instead of enumerating counts we directly check this one
// fixed, maximally-different value rejects.
func TestNegativeCountForcedToMax(t *testing.T) {
	for variant, vp := range firstVectorPerVariant(t) {
		variant, vp := variant, vp
		t.Run(variant, func(t *testing.T) {
			p := vp.p
			msg, pkSeed, pkRoot, sig := vectorInputs(t, vp.e)

			htStart := p.HTStart()
			layerSize := p.LayerSize()
			l := p.L

			for layer := 0; layer < p.D; layer++ {
				countOff := htStart + layer*layerSize + l*p.N
				mutated := make([]byte, len(sig))
				copy(mutated, sig)
				binary.BigEndian.PutUint32(mutated[countOff:countOff+4], 0xFFFFFFFF)
				if Verify(p, pkSeed, pkRoot, msg, mutated) {
					t.Errorf("layer %d: count forced to 0xFFFFFFFF still verifies", layer)
				}
			}
		})
	}
}

// TestVerifyMalformedInputs checks that Verify rejects (returns false,
// never panics on) a battery of malformed top-level inputs: nil Params,
// a nil or empty signature, and a message that is 31 or 33 bytes instead
// of exactly 32 (SPEC §1).
func TestVerifyMalformedInputs(t *testing.T) {
	vp := firstVectorPerVariant(t)["C11"]
	msg, pkSeed, pkRoot, sig := vectorInputs(t, vp.e)

	if Verify(nil, pkSeed, pkRoot, msg, sig) {
		t.Error("Verify(nil params, ...) = true, want false")
	}
	if Verify(vp.p, pkSeed, pkRoot, msg, nil) {
		t.Error("Verify(..., nil sig) = true, want false")
	}
	if Verify(vp.p, pkSeed, pkRoot, msg, []byte{}) {
		t.Error("Verify(..., empty sig) = true, want false")
	}
	if Verify(vp.p, pkSeed, pkRoot, msg[:31], sig) {
		t.Error("Verify(..., 31-byte msg, ...) = true, want false")
	}
	msg33 := append(append([]byte{}, msg...), 0x00)
	if Verify(vp.p, pkSeed, pkRoot, msg33, sig) {
		t.Error("Verify(..., 33-byte msg, ...) = true, want false")
	}
}

// TestPublicKeyVerifyMismatchedParams checks PublicKey.Verify with a
// Params value that doesn't match the signature it's asked to check: a
// PublicKey configured for C13 (whose SigBytes() differs from every
// other variant) rejects a C11-length signature outright via the length
// check, rather than misinterpreting its bytes under the wrong layout.
func TestPublicKeyVerifyMismatchedParams(t *testing.T) {
	byVariant := firstVectorPerVariant(t)
	c11 := byVariant["C11"]
	c13 := byVariant["C13"]

	if c11.p.SigBytes() == c13.p.SigBytes() {
		t.Fatalf("test assumption violated: C11 and C13 SigBytes() coincide")
	}

	c11Msg, c11Seed, c11Root, c11Sig := vectorInputs(t, c11.e)

	// A PublicKey declared as C13 params but holding a C11 vector's seed
	// material/signature: the length check in Verify must reject this
	// before any hash is computed.
	pk := &PublicKey{Params: c13.p, Seed: c11Seed, Root: c11Root}
	if pk.Verify(c11Msg, c11Sig) {
		t.Error("PublicKey.Verify with mismatched Params (C13 key, C11-length sig) = true, want false")
	}
}
