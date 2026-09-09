package sphincsminus

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// FuzzVerify seeds from a real, verifying C13 reference vector and then
// mutates pkSeed/pkRoot/msg/sig arbitrarily. Verify must never panic,
// regardless of length or content; the corpus is not checked for a
// particular return value since most mutations are expected to make it
// return false, but some (e.g. the identity mutation) must return true.
func FuzzVerify(f *testing.F) {
	vf := loadVectorFileForFuzz(f, "testdata/vectors/c13.json")
	for _, e := range vf.Vectors {
		msg := mustDecodeHexForFuzz(f, e.Message)
		seedFull := mustDecodeHexForFuzz(f, e.PkSeed)
		rootFull := mustDecodeHexForFuzz(f, e.PkRoot)
		sig := mustDecodeHexForFuzz(f, e.Signature)
		if len(seedFull) != 32 || len(rootFull) != 32 {
			continue
		}
		f.Add(seedFull[:16], rootFull[:16], msg, sig)
	}
	// A handful of deliberately-malformed extra seeds: empty/short/huge
	// inputs are exactly the adversarial shapes Verify must survive.
	f.Add([]byte{}, []byte{}, []byte{}, []byte{})
	f.Add(make([]byte, 16), make([]byte, 16), make([]byte, 32), make([]byte, 1))
	f.Add(make([]byte, 16), make([]byte, 16), make([]byte, 32), make([]byte, 100000))

	f.Fuzz(func(t *testing.T, seed, root, msg, sig []byte) {
		for _, p := range AllParams {
			var s, r [16]byte
			copy(s[:], seed)
			copy(r[:], root)
			// Verify must never panic no matter what garbage it's fed.
			_ = Verify(p, s, r, msg, sig)
		}
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
