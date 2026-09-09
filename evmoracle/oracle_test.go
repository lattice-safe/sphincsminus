package evmoracle

import (
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	sphincsminus "github.com/lattice-safe/sphincsminus"
)

// vectorFile / vectorEntry mirror the schema of ../testdata/vectors/*.json
// (see the root package's vectors_test.go). Only the fields this package
// needs are decoded.
type vectorFile struct {
	Variant string        `json:"variant"`
	Vectors []vectorEntry `json:"vectors"`
}

type vectorEntry struct {
	Name      string `json:"name"`
	Message   string `json:"message"`
	PkSeed    string `json:"pkSeed"`
	PkRoot    string `json:"pkRoot"`
	Signature string `json:"signature"`
}

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func word32(t *testing.T, s string) [32]byte {
	t.Helper()
	b := decodeHex(t, s)
	if len(b) != 32 {
		t.Fatalf("expected 32 bytes, got %d (%q)", len(b), s)
	}
	var w [32]byte
	copy(w[:], b)
	return w
}

// loadVectorFiles reads every ../testdata/vectors/*.json file, sorted by
// path for deterministic test ordering.
func loadVectorFiles(t *testing.T) []vectorFile {
	t.Helper()
	paths, err := filepath.Glob("../testdata/vectors/*.json")
	if err != nil {
		t.Fatalf("glob ../testdata/vectors/*.json: %v", err)
	}
	if len(paths) == 0 {
		t.Fatalf("no vector files found under ../testdata/vectors/")
	}
	sort.Strings(paths)
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

// flipByte returns a copy of b with bit 0 of byte i flipped.
func flipByte(b []byte, i int) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	out[i] ^= 0x01
	return out
}

// goVerify16 adapts a top-aligned 32-byte pkSeed/pkRoot word to the
// [16]byte shape sphincsminus.Verify wants.
func to16(w [32]byte) [16]byte {
	var out [16]byte
	copy(out[:], w[:16])
	return out
}

// TestReferenceVectorsOnChain checks that every vector in
// ../testdata/vectors/*.json is accepted (returns true, no revert) by
// the real compiled Solidity verifier bytecode running in go-ethereum's
// EVM, and logs the gas used per vector.
func TestReferenceVectorsOnChain(t *testing.T) {
	for _, vf := range loadVectorFiles(t) {
		vf := vf
		t.Run(vf.Variant, func(t *testing.T) {
			p, ok := sphincsminus.ParamsByName(vf.Variant)
			if !ok {
				t.Fatalf("unknown variant %q", vf.Variant)
			}
			v, err := LoadVerifier(p)
			if err != nil {
				t.Fatalf("LoadVerifier(%s): %v", vf.Variant, err)
			}
			for _, e := range vf.Vectors {
				e := e
				t.Run(e.Name, func(t *testing.T) {
					msg := word32(t, e.Message)
					pkSeed := word32(t, e.PkSeed)
					pkRoot := word32(t, e.PkRoot)
					sig := decodeHex(t, e.Signature)

					valid, gas, err := v.Verify(pkSeed, pkRoot, msg, sig)
					if err != nil {
						t.Fatalf("Verify(%s/%s): unexpected revert: %v", vf.Variant, e.Name, err)
					}
					if !valid {
						t.Fatalf("Verify(%s/%s) = false, want true", vf.Variant, e.Name)
					}
					t.Logf("%s/%s: gasUsed=%d", vf.Variant, e.Name, gas)
				})
			}
		})
	}
}

// slowVariants are only exercised on-chain when SPHINCSMINUS_SLOW=1,
// mirroring the root package's convention for the more expensive C7/C13
// sign roundtrips (docs/PLAN.md, Phase 3a).
var slowVariants = map[string]bool{"C7": true, "C13": true}

func slowEnabled() bool {
	return os.Getenv("SPHINCSMINUS_SLOW") == "1"
}

// TestGoSignaturesOnChain generates a fresh key, signs two random
// 32-byte messages with the Go signer, and checks that both the Go
// Verify and the real on-chain Solidity verifier agree the signatures
// are valid. C11/C10/C9 always run; C7/C13 only run under
// SPHINCSMINUS_SLOW=1 (full C7/C13 signing is comparatively slow).
func TestGoSignaturesOnChain(t *testing.T) {
	variants := []*sphincsminus.Params{sphincsminus.C11, sphincsminus.C10, sphincsminus.C9}
	if slowEnabled() {
		variants = append(variants, sphincsminus.C7, sphincsminus.C13)
	} else {
		t.Log("SPHINCSMINUS_SLOW not set: skipping C7/C13 (set SPHINCSMINUS_SLOW=1 to include them)")
	}

	rng := rand.New(rand.NewSource(1))

	for _, p := range variants {
		p := p
		t.Run(p.Name, func(t *testing.T) {
			sk, err := sphincsminus.GenerateKey(p)
			if err != nil {
				t.Fatalf("GenerateKey(%s): %v", p.Name, err)
			}
			v, err := LoadVerifier(p)
			if err != nil {
				t.Fatalf("LoadVerifier(%s): %v", p.Name, err)
			}

			for i := 0; i < 2; i++ {
				var msg [32]byte
				if _, err := rng.Read(msg[:]); err != nil {
					t.Fatalf("rng.Read: %v", err)
				}

				sig, err := sk.Sign(msg[:])
				if err != nil {
					t.Fatalf("Sign: %v", err)
				}

				if !sk.PublicKey.Verify(msg[:], sig) {
					t.Fatalf("%s msg#%d: Go Verify = false, want true", p.Name, i)
				}

				valid, gas, err := v.Verify(sk.PublicKey.SeedWord(), sk.PublicKey.RootWord(), msg, sig)
				if err != nil {
					t.Fatalf("%s msg#%d: on-chain Verify: unexpected revert: %v", p.Name, i, err)
				}
				if !valid {
					t.Fatalf("%s msg#%d: on-chain Verify = false, want true", p.Name, i)
				}
				t.Logf("%s msg#%d: gasUsed=%d", p.Name, i, gas)
			}
		})
	}
}

// TestMutationsOnChain exercises the SPEC §12 on-chain failure
// semantics against one vector per variant: a length mutation, a
// last-layer WOTS chain byte, a FORS secret byte, and a non-canonical
// pkRoot. In every case it also asserts the Go Verify rejects the
// mutation (it always returns false, never panics/errors).
func TestMutationsOnChain(t *testing.T) {
	for _, vf := range loadVectorFiles(t) {
		vf := vf
		t.Run(vf.Variant, func(t *testing.T) {
			p, ok := sphincsminus.ParamsByName(vf.Variant)
			if !ok {
				t.Fatalf("unknown variant %q", vf.Variant)
			}
			if len(vf.Vectors) == 0 {
				t.Fatalf("no vectors for %s", vf.Variant)
			}
			e := vf.Vectors[0]

			v, err := LoadVerifier(p)
			if err != nil {
				t.Fatalf("LoadVerifier(%s): %v", vf.Variant, err)
			}

			msg := word32(t, e.Message)
			pkSeed := word32(t, e.PkSeed)
			pkRoot := word32(t, e.PkRoot)
			sig := decodeHex(t, e.Signature)

			// Sanity: the baseline vector must verify both on-chain and
			// in Go before mutating it.
			if valid, _, err := v.Verify(pkSeed, pkRoot, msg, sig); err != nil || !valid {
				t.Fatalf("baseline vector does not verify on-chain (valid=%v err=%v)", valid, err)
			}
			if !sphincsminus.Verify(p, to16(pkSeed), to16(pkRoot), msg[:], sig) {
				t.Fatalf("baseline vector does not verify in Go")
			}

			n := p.N

			t.Run("truncated_length", func(t *testing.T) {
				mutated := sig[:len(sig)-1]

				valid, _, err := v.Verify(pkSeed, pkRoot, msg, mutated)
				if err == nil {
					t.Fatalf("on-chain Verify with truncated sig did not revert (valid=%v)", valid)
				}
				re, ok := err.(*revertError)
				if !ok {
					t.Fatalf("expected *revertError, got %T: %v", err, err)
				}
				if !strings.Contains(re.Reason(), "Invalid sig length") {
					t.Errorf("revert reason = %q, want it to contain %q", re.Reason(), "Invalid sig length")
				}

				if sphincsminus.Verify(p, to16(pkSeed), to16(pkRoot), msg[:], mutated) {
					t.Errorf("Go Verify accepted a truncated signature")
				}
			})

			t.Run("wots_chain_last_layer", func(t *testing.T) {
				lastLayerOffset := p.HTStart() + (p.D-1)*p.LayerSize()
				mutated := flipByte(sig, lastLayerOffset)

				valid, _, err := v.Verify(pkSeed, pkRoot, msg, mutated)
				if err != nil {
					t.Fatalf("on-chain Verify unexpectedly reverted: %v", err)
				}
				if valid {
					t.Errorf("on-chain Verify accepted a corrupted last-layer WOTS chain byte")
				}

				if sphincsminus.Verify(p, to16(pkSeed), to16(pkRoot), msg[:], mutated) {
					t.Errorf("Go Verify accepted a corrupted last-layer WOTS chain byte")
				}
			})

			t.Run("fors_secret", func(t *testing.T) {
				forsSecretOffset := n // tree t=0's secret, not the forced-zero tree (k-1)
				mutated := flipByte(sig, forsSecretOffset)

				valid, _, err := v.Verify(pkSeed, pkRoot, msg, mutated)
				switch vf.Variant {
				case "C13":
					if err != nil {
						t.Fatalf("C13 on-chain Verify unexpectedly reverted: %v", err)
					}
					if valid {
						t.Errorf("C13 on-chain Verify accepted a corrupted FORS secret byte")
					}
				default:
					if err == nil {
						t.Fatalf("%s on-chain Verify did not revert on a corrupted FORS secret byte (valid=%v)", vf.Variant, valid)
					}
				}

				if sphincsminus.Verify(p, to16(pkSeed), to16(pkRoot), msg[:], mutated) {
					t.Errorf("Go Verify accepted a corrupted FORS secret byte")
				}
			})

			t.Run("noncanonical_pkroot", func(t *testing.T) {
				badRoot := pkRoot
				badRoot[16] ^= 0x01 // low 16 bytes of pkRoot must be zero (N_MASK form)

				valid, _, err := v.Verify(pkSeed, badRoot, msg, sig)
				if err == nil {
					t.Fatalf("on-chain Verify with non-canonical pkRoot did not revert (valid=%v)", valid)
				}
				re, ok := err.(*revertError)
				if !ok {
					t.Fatalf("expected *revertError, got %T: %v", err, err)
				}
				if !strings.Contains(re.Reason(), "Invalid public key") {
					t.Errorf("revert reason = %q, want it to contain %q", re.Reason(), "Invalid public key")
				}

				// No Go-side assertion here: sphincsminus.Verify's
				// pkRoot parameter is [16]byte, so there is no way to
				// even construct a "non-canonical" (low-16-bytes
				// nonzero) root through the Go API — to16 would just
				// discard the mutated low half we set above. The
				// canonical-root check is purely an on-chain ABI-level
				// concern for this library. See the Phase 3a report for
				// this observation.
			})
		})
	}
}

// TestGasTable logs a markdown table of variant -> gas used for the
// first reference vector of each variant, suitable for pasting into the
// README's gas table.
func TestGasTable(t *testing.T) {
	t.Log("| variant | vector | gas used |")
	t.Log("|---|---|---|")
	for _, vf := range loadVectorFiles(t) {
		p, ok := sphincsminus.ParamsByName(vf.Variant)
		if !ok || len(vf.Vectors) == 0 {
			continue
		}
		v, err := LoadVerifier(p)
		if err != nil {
			t.Fatalf("LoadVerifier(%s): %v", vf.Variant, err)
		}
		e := vf.Vectors[0]
		msg := word32(t, e.Message)
		pkSeed := word32(t, e.PkSeed)
		pkRoot := word32(t, e.PkRoot)
		sig := decodeHex(t, e.Signature)

		valid, gas, err := v.Verify(pkSeed, pkRoot, msg, sig)
		if err != nil || !valid {
			t.Fatalf("%s: Verify failed (valid=%v err=%v)", vf.Variant, valid, err)
		}
		t.Logf("| %s | %s | %d |", vf.Variant, e.Name, gas)
	}
}
