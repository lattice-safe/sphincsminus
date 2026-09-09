package sphincsminus

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHexWord(t *testing.T, s string) word {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	if len(b) != 32 {
		t.Fatalf("hex %q decodes to %d bytes, want 32", s, len(b))
	}
	var w word
	copy(w[:], b)
	return w
}

// TestPrfKATs checks the four KATs given directly in SPEC §3.2, which use
// entropy = 0x42*32 fed straight into "pk_seed"/"sk_seed" hashing (i.e.
// seedsFromEntropy), not the material-wrapped deriveReferenceSeeds.
func TestPrfKATs(t *testing.T) {
	var entropy word
	for i := range entropy {
		entropy[i] = 0x42
	}

	wantPkSeed := mustHexWord(t, "012dd57311a3728fd6988fb2a583bb9e00000000000000000000000000000000")
	wantSkSeed := mustHexWord(t, "11d47d1635d4ad4852852dae8fd9dbbd699558d7907907cdae4203bdbae7f7aa")

	pkSeed, skSeed := seedsFromEntropy(entropy)
	if pkSeed != wantPkSeed {
		t.Errorf("pkSeed = %x, want %x", pkSeed, wantPkSeed)
	}
	if skSeed != wantSkSeed {
		t.Errorf("skSeed = %x, want %x", skSeed, wantSkSeed)
	}

	wantWotsSecret := mustHexWord(t, "60fd5cf59c3c018fca334b8538cc52fe00000000000000000000000000000000")
	gotWotsSecret := wotsSecret(skSeed, 1, 0, 0, 0)
	if gotWotsSecret != wantWotsSecret {
		t.Errorf("wotsSecret(skSeed, layer=1, tree=0, kp=0, chain=0) = %x, want %x", gotWotsSecret, wantWotsSecret)
	}

	wantForsSecret := mustHexWord(t, "f3c46060303099c9faed1691ad98823900000000000000000000000000000000")
	gotForsSecret := forsSecret(skSeed, 0, 0, 0)
	if gotForsSecret != wantForsSecret {
		t.Errorf("forsSecret(skSeed, htIdx=0, t=0, j=0) = %x, want %x", gotForsSecret, wantForsSecret)
	}
}

// TestDeriveReferenceSeedsC13Vector checks deriveReferenceSeeds(material)
// against testdata/vectors/c13.json's "c13_signwith_material42_deadbeef"
// vector, whose material is 32 bytes of 0x42 (i.e. the wrapped path,
// entropy = keccak256("sphincs_signer_v1" ‖ 0x42*32), unlike the raw KAT
// above).
func TestDeriveReferenceSeedsC13Vector(t *testing.T) {
	var material [32]byte
	for i := range material {
		material[i] = 0x42
	}

	wantPkSeed := mustHexWord(t, "1425183fe80b1ffc9e5ac508c5815ff200000000000000000000000000000000")
	wantSkSeed := mustHexWord(t, "561c62f87ea9e7c8062bc1166d72410de1cfd2e8c9ae64ad120c21351fd6c431")

	pkSeed, skSeed := deriveReferenceSeeds(material)
	if pkSeed != wantPkSeed {
		t.Errorf("deriveReferenceSeeds pkSeed = %x, want %x", pkSeed, wantPkSeed)
	}
	if skSeed != wantSkSeed {
		t.Errorf("deriveReferenceSeeds skSeed = %x, want %x", skSeed, wantSkSeed)
	}
}

func TestMaskN(t *testing.T) {
	var w word
	for i := range w {
		w[i] = 0xAB
	}
	m := maskN(w)
	if !bytes.Equal(m[:16], w[:16]) {
		t.Errorf("maskN changed the top 16 bytes")
	}
	for i := 16; i < 32; i++ {
		if m[i] != 0 {
			t.Errorf("maskN left byte %d = %#x, want 0", i, m[i])
		}
	}
}
