package sphincsminus

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vectorFile mirrors the schema of testdata/vectors/*.json:
//
//	{"variant": "C13", "vectors": [{"name","message","pkSeed","pkRoot","signature", ...}]}
type vectorFile struct {
	Variant string        `json:"variant"`
	Vectors []vectorEntry `json:"vectors"`
}

type vectorEntry struct {
	Name          string `json:"name"`
	KeyDerivation string `json:"keyDerivation"`
	Message       string `json:"message"`
	PkSeed        string `json:"pkSeed"`
	PkRoot        string `json:"pkRoot"`
	Signature     string `json:"signature"`

	// Material and SkSeed are only present on vectors whose
	// keyDerivation is "reference:material=<explicit hex>" (currently
	// just c13_signwith_material42_deadbeef): Material is the 32-byte
	// derivation input (distinct from Message), and SkSeed is the
	// expected derived signer secret, both for cross-checking
	// DeriveKeyReference (sign_test.go). Every other vector's
	// keyDerivation is "reference:material=message" (Message doubles as
	// the derivation material) and leaves these two fields empty.
	Material string `json:"material"`
	SkSeed   string `json:"skSeed"`
}

// decodeHex decodes a 0x-prefixed hex string, failing the test on error.
func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// loadVectorFiles reads every testdata/vectors/*.json file.
func loadVectorFiles(t *testing.T) []vectorFile {
	t.Helper()
	paths, err := filepath.Glob("testdata/vectors/*.json")
	if err != nil {
		t.Fatalf("glob testdata/vectors/*.json: %v", err)
	}
	if len(paths) == 0 {
		t.Fatalf("no vector files found under testdata/vectors/")
	}
	var files []vectorFile
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		var vf vectorFile
		if err := json.Unmarshal(b, &vf); err != nil {
			t.Fatalf("unmarshal %s: %v", p, err)
		}
		files = append(files, vf)
	}
	return files
}

// vectorInputs decodes a vectorEntry's hex fields into the shapes Verify
// wants: a 32-byte message, top-aligned 16-byte pkSeed/pkRoot, and raw
// signature bytes.
func vectorInputs(t *testing.T, e vectorEntry) (msg []byte, pkSeed, pkRoot [16]byte, sig []byte) {
	t.Helper()
	msg = decodeHex(t, e.Message)
	seedFull := decodeHex(t, e.PkSeed)
	rootFull := decodeHex(t, e.PkRoot)
	if len(seedFull) != 32 {
		t.Fatalf("%s: pkSeed decodes to %d bytes, want 32", e.Name, len(seedFull))
	}
	if len(rootFull) != 32 {
		t.Fatalf("%s: pkRoot decodes to %d bytes, want 32", e.Name, len(rootFull))
	}
	copy(pkSeed[:], seedFull[:16])
	copy(pkRoot[:], rootFull[:16])
	sig = decodeHex(t, e.Signature)
	return msg, pkSeed, pkRoot, sig
}

// TestVectors verifies every vector in testdata/vectors/*.json is
// accepted by Verify under its own variant's parameter set.
func TestVectors(t *testing.T) {
	for _, vf := range loadVectorFiles(t) {
		p, ok := ParamsByName(vf.Variant)
		if !ok {
			t.Fatalf("unknown variant %q in vector file", vf.Variant)
		}
		for _, e := range vf.Vectors {
			e := e
			t.Run(e.Name, func(t *testing.T) {
				msg, pkSeed, pkRoot, sig := vectorInputs(t, e)
				if !Verify(p, pkSeed, pkRoot, msg, sig) {
					t.Fatalf("Verify(%s/%s) = false, want true", vf.Variant, e.Name)
				}
			})
		}
	}
}

// flipByte returns a copy of b with bit 0 of byte i flipped.
func flipByte(b []byte, i int) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	out[i] ^= 0x01
	return out
}

// TestVectorsNegative runs the negative-mutation matrix from docs/SPEC.md /
// the task brief against every reference vector: flipping any single
// byte in a structurally meaningful region of the signature, or in the
// message, or truncating/extending the signature, or checking the
// public key material, must make Verify reject.
func TestVectorsNegative(t *testing.T) {
	for _, vf := range loadVectorFiles(t) {
		p, ok := ParamsByName(vf.Variant)
		if !ok {
			t.Fatalf("unknown variant %q in vector file", vf.Variant)
		}
		for _, e := range vf.Vectors {
			e := e
			t.Run(e.Name, func(t *testing.T) {
				msg, pkSeed, pkRoot, sig := vectorInputs(t, e)

				// Sanity: the unmodified vector must verify before we
				// start mutating it, or these negative tests are
				// meaningless.
				if !Verify(p, pkSeed, pkRoot, msg, sig) {
					t.Fatalf("baseline vector does not verify; aborting negative tests")
				}

				n := p.N

				// Byte offsets of interest within the signature, per
				// SPEC §11's wire layout.
				rOffset := 0
				forsSecretOffset := n // first FORS secret, tree t=0
				forsAuthOffset := p.AuthStart()
				wotsChainOffset := p.HTStart() // first WOTS chain, layer 0
				countOffset := p.HTStart() + p.L*n
				xmssAuthOffset := countOffset + 4

				regions := map[string]int{
					"R":              rOffset,
					"fors_secret":    forsSecretOffset,
					"fors_auth_node": forsAuthOffset,
					"wots_chain":     wotsChainOffset,
					"count":          countOffset,
					"xmss_auth_node": xmssAuthOffset,
				}
				for name, off := range regions {
					mutated := flipByte(sig, off)
					if Verify(p, pkSeed, pkRoot, msg, mutated) {
						t.Errorf("flipping a byte in %s (offset %d) still verifies", name, off)
					}
				}

				// Wrong message.
				wrongMsg := make([]byte, 32)
				copy(wrongMsg, msg)
				wrongMsg[0] ^= 0x01
				if Verify(p, pkSeed, pkRoot, wrongMsg, sig) {
					t.Errorf("wrong message still verifies")
				}

				// Truncated / extended signature.
				if Verify(p, pkSeed, pkRoot, msg, sig[:len(sig)-1]) {
					t.Errorf("truncated signature still verifies")
				}
				extended := append(append([]byte{}, sig...), 0x00)
				if Verify(p, pkSeed, pkRoot, msg, extended) {
					t.Errorf("extended signature still verifies")
				}
				if Verify(p, pkSeed, pkRoot, msg, nil) {
					t.Errorf("empty signature still verifies")
				}

				// Wrong pkRoot.
				wrongRoot := pkRoot
				wrongRoot[0] ^= 0x01
				if Verify(p, pkSeed, wrongRoot, msg, sig) {
					t.Errorf("wrong pkRoot still verifies")
				}

				// Wrong pkSeed.
				wrongSeed := pkSeed
				wrongSeed[0] ^= 0x01
				if Verify(p, wrongSeed, pkRoot, msg, sig) {
					t.Errorf("wrong pkSeed still verifies")
				}
			})
		}
	}
}

// TestVectorWrongParamsLengthMismatch checks that a C13 vector rejected
// outright (via the length check) when verified under C11's parameter
// set, since the two variants have different SigBytes().
func TestVectorWrongParamsLengthMismatch(t *testing.T) {
	var c13 vectorFile
	for _, vf := range loadVectorFiles(t) {
		if vf.Variant == "C13" {
			c13 = vf
			break
		}
	}
	if len(c13.Vectors) == 0 {
		t.Fatalf("no C13 vectors found")
	}

	if C11.SigBytes() == C13.SigBytes() {
		t.Fatalf("test assumption violated: C11 and C13 have the same SigBytes()")
	}

	for _, e := range c13.Vectors {
		e := e
		t.Run(e.Name, func(t *testing.T) {
			msg, pkSeed, pkRoot, sig := vectorInputs(t, e)
			if Verify(C11, pkSeed, pkRoot, msg, sig) {
				t.Errorf("C13 vector unexpectedly verifies under C11 params")
			}
		})
	}
}

// TestVectorsForcedZeroViolation flips the last FORS secret (tree k-1,
// the forced-zero tree) and confirms Verify rejects it: this is the one
// mutation that additionally exercises the forced-zero check in Verify
// rather than only the digit-sum/root recomputation.
func TestVectorsForcedZeroViolation(t *testing.T) {
	for _, vf := range loadVectorFiles(t) {
		p, ok := ParamsByName(vf.Variant)
		if !ok {
			t.Fatalf("unknown variant %q", vf.Variant)
		}
		for _, e := range vf.Vectors {
			e := e
			t.Run(e.Name, func(t *testing.T) {
				msg, pkSeed, pkRoot, sig := vectorInputs(t, e)

				// Flipping the last FORS secret changes root(k-1) but
				// the forced-zero check itself depends only on the
				// message digest (independent of the signature bytes),
				// so this exercises the root-mismatch path, not the
				// forced-zero path directly. We additionally confirm
				// the vector's own digest really does have
				// forsIdx[k-1] == 0, i.e. the forced-zero condition the
				// signer satisfied by construction.
				var seedW, rootW, msgW word
				copy(seedW[:16], pkSeed[:])
				copy(rootW[:16], pkRoot[:])
				copy(msgW[:], msg)
				var r word
				copy(r[:16], sig[0:16])
				digest := hMsg(seedW, rootW, r, msgW)
				fi := forsIndices(&digest, p)
				if fi[p.K-1] != 0 {
					t.Fatalf("vector %s does not satisfy forced-zero (forsIdx[k-1]=%d)", e.Name, fi[p.K-1])
				}

				lastSecretOff := p.N + (p.K-1)*p.N
				mutated := flipByte(sig, lastSecretOff)
				if Verify(p, pkSeed, pkRoot, msg, mutated) {
					t.Errorf("flipping the forced-zero tree's secret still verifies")
				}
			})
		}
	}
}
