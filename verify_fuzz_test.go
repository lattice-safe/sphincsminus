package sphincsminus

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// FuzzVerify seeds from a real, verifying C13 reference vector and then
// mutates pkSeed/pkRoot/msg/sig/paramIdx arbitrarily -- paramIdx selects
// which of AllParams to verify under, so the fuzzing engine can explore
// the parameter-set dimension (e.g. a C13-shaped signature checked
// against C11's SigBytes()) the same way it explores every other byte of
// the input, rather than this test always trying every parameter set
// for every mutation. Verify must never panic, regardless of length or
// content; the corpus is not checked for a particular return value since
// most mutations are expected to make it return false, but some (e.g.
// the identity mutation under C13) must return true.
func FuzzVerify(f *testing.F) {
	var c13Idx byte
	for i, p := range AllParams {
		if p == C13 {
			c13Idx = byte(i)
			break
		}
	}

	vf := loadVectorFileForFuzz(f, "testdata/vectors/c13.json")
	for _, e := range vf.Vectors {
		msg := mustDecodeHexForFuzz(f, e.Message)
		seedFull := mustDecodeHexForFuzz(f, e.PkSeed)
		rootFull := mustDecodeHexForFuzz(f, e.PkRoot)
		sig := mustDecodeHexForFuzz(f, e.Signature)
		if len(seedFull) != 32 || len(rootFull) != 32 {
			continue
		}
		// These vectors are genuine C13 signatures, so seed the corpus
		// with paramIdx pointing at C13 (the identity mutation should
		// then verify true); the fuzzer is free to mutate paramIdx to
		// any other value from there.
		f.Add(seedFull[:16], rootFull[:16], msg, sig, c13Idx)
	}
	// A handful of deliberately-malformed extra seeds: empty/short/huge
	// inputs are exactly the adversarial shapes Verify must survive,
	// under every parameter set index (including out-of-range ones,
	// reduced mod len(AllParams) below).
	f.Add([]byte{}, []byte{}, []byte{}, []byte{}, byte(0))
	f.Add(make([]byte, 16), make([]byte, 16), make([]byte, 32), make([]byte, 1), byte(255))
	f.Add(make([]byte, 16), make([]byte, 16), make([]byte, 32), make([]byte, 100000), byte(4))

	f.Fuzz(func(t *testing.T, seed, root, msg, sig []byte, paramIdx byte) {
		p := AllParams[int(paramIdx)%len(AllParams)]
		var s, r [16]byte
		copy(s[:], seed)
		copy(r[:], root)
		// Verify must never panic no matter what garbage it's fed.
		_ = Verify(p, s, r, msg, sig)
	})
}

// The helpers below duplicate a little of vectors_test.go's JSON loading
// because *testing.F (fuzz seed setup) needs its own Fatalf-capable
// helper type, and reusing *testing.T's Helper() there would be
// misleading.

func loadVectorFileForFuzz(f *testing.F, path string) vectorFile {
	f.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		f.Fatalf("read %s: %v", path, err)
	}
	var vf vectorFile
	if err := json.Unmarshal(b, &vf); err != nil {
		f.Fatalf("unmarshal %s: %v", path, err)
	}
	return vf
}

func mustDecodeHexForFuzz(f *testing.F, s string) []byte {
	f.Helper()
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		f.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}
