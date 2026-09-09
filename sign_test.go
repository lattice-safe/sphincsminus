package sphincsminus

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

// slowEnv is the environment variable that gates the expensive C7/C13
// full-sign vector and roundtrip tests (SPHINCSMINUS_SLOW=1, see
// CLAUDE.md). C13's expected R-grind cost alone is 2^19 attempts; C7's is
// 2^16. Both are well under a minute on a modern multi-core machine (see
// BenchmarkSignC13 for the measured number) but are still too slow for
// the default `go test ./...` inner loop.
const slowEnv = "SPHINCSMINUS_SLOW"

func slowTestsEnabled() bool {
	return os.Getenv(slowEnv) == "1"
}

func skipUnlessSlow(t *testing.T, variant string) {
	t.Helper()
	if !slowTestsEnabled() {
		t.Skipf("skipping slow %s full-sign test; set %s=1 to run it (expect several seconds)", variant, slowEnv)
	}
}

// TestSignVectors is the pinning test for the whole Phase 2 signer: for
// every vector in testdata/vectors/*.json, it derives the signing key
// exactly the way the vector says to (DeriveKeyReference on either the
// message or, for c13_signwith_material42_deadbeef, an explicit
// material/skSeed pair), checks the derived pkSeed/pkRoot/skSeed against
// the vector, signs the vector's message, and asserts the result is
// byte-identical to the vector's signature. This pins the R grind, the
// WOTS+C count grind, and every PRF simultaneously: any divergence at any
// layer shows up as a mismatch here.
//
// C9/C10/C11 vectors always run (they're fast: no vector's R-grind here
// exceeds roughly 2^13 expected attempts). C7 and C13 are gated behind
// SPHINCSMINUS_SLOW=1 (SPEC's a=16 and a=19 respectively mean expected
// R-grind costs of 2^16 and 2^19 attempts).
func TestSignVectors(t *testing.T) {
	for _, vf := range loadVectorFiles(t) {
		vf := vf
		p, ok := ParamsByName(vf.Variant)
		if !ok {
			t.Fatalf("unknown variant %q in vector file", vf.Variant)
		}
		for _, e := range vf.Vectors {
			e := e
			t.Run(e.Name, func(t *testing.T) {
				if vf.Variant == "C7" || vf.Variant == "C13" {
					skipUnlessSlow(t, vf.Variant)
				}

				msg, wantSeed16, wantRoot16, wantSig := vectorInputs(t, e)

				var material [32]byte
				var wantSkSeed *[32]byte
				if e.Material != "" {
					// c13_signwith_material42_deadbeef: explicit
					// material distinct from the message, plus an
					// expected skSeed to check against.
					mb := decodeHex(t, e.Material)
					if len(mb) != 32 {
						t.Fatalf("%s: material decodes to %d bytes, want 32", e.Name, len(mb))
					}
					copy(material[:], mb)

					skb := decodeHex(t, e.SkSeed)
					if len(skb) != 32 {
						t.Fatalf("%s: skSeed decodes to %d bytes, want 32", e.Name, len(skb))
					}
					var sk32 [32]byte
					copy(sk32[:], skb)
					wantSkSeed = &sk32
				} else {
					// Every other vector: keyDerivation is
					// "reference:material=message".
					copy(material[:], msg)
				}

				sk, err := DeriveKeyReference(p, material)
				if err != nil {
					t.Fatalf("DeriveKeyReference: %v", err)
				}

				if wantSkSeed != nil && sk.SkSeed != *wantSkSeed {
					t.Fatalf("SkSeed = %x, want %x", sk.SkSeed, *wantSkSeed)
				}
				if sk.PublicKey.Seed != wantSeed16 {
					t.Fatalf("pkSeed = %x, want %x", sk.PublicKey.Seed, wantSeed16)
				}
				if sk.PublicKey.Root != wantRoot16 {
					t.Fatalf("pkRoot = %x, want %x", sk.PublicKey.Root, wantRoot16)
				}

				sig, err := sk.Sign(msg)
				if err != nil {
					t.Fatalf("Sign: %v", err)
				}
				if !bytes.Equal(sig, wantSig) {
					off := firstMismatch(sig, wantSig)
					t.Fatalf("%s: signature mismatch at byte offset %d (len got=%d want=%d)\ngot:  %x\nwant: %x",
						e.Name, off, len(sig), len(wantSig), sig, wantSig)
				}

				// A byte-identical signature must of course also
				// verify.
				if !sk.PublicKey.Verify(msg, sig) {
					t.Fatalf("%s: produced signature does not verify", e.Name)
				}
			})
		}
	}
}

// firstMismatch returns the index of the first differing byte between a
// and b, or the length of the shorter slice if one is a prefix of the
// other (or -1 if they're equal), to make a byte-identical-signature
// test failure point straight at the offending signature region instead
// of dumping the whole thing.
func firstMismatch(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	if len(a) != len(b) {
		return n
	}
	return -1
}

// TestSignRoundtripC11 is the fast (always-run) roundtrip check: a fresh
// random C11 key signs a message, the signature verifies under that
// key's public key, and a wrong message is rejected.
func TestSignRoundtripC11(t *testing.T) {
	sk, err := GenerateKey(C11)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	msg := make([]byte, 32)
	for i := range msg {
		msg[i] = byte(i)
	}

	sig, err := sk.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !sk.PublicKey.Verify(msg, sig) {
		t.Fatal("Verify(correct message) = false, want true")
	}

	wrongMsg := make([]byte, 32)
	copy(wrongMsg, msg)
	wrongMsg[0] ^= 0x01
	if sk.PublicKey.Verify(wrongMsg, sig) {
		t.Fatal("Verify(wrong message) = true, want false")
	}
}

// TestSignRoundtripSlowAllParams roundtrips every parameter set
// (including C7 and C13) under SPHINCSMINUS_SLOW=1.
func TestSignRoundtripSlowAllParams(t *testing.T) {
	if !slowTestsEnabled() {
		t.Skipf("skipping full-parameter-set roundtrip; set %s=1 to run it", slowEnv)
	}

	for _, p := range AllParams {
		p := p
		t.Run(p.Name, func(t *testing.T) {
			sk, err := GenerateKey(p)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}

			msg := make([]byte, 32)
			for i := range msg {
				msg[i] = byte(i * 7)
			}

			sig, err := sk.Sign(msg)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !sk.PublicKey.Verify(msg, sig) {
				t.Fatal("Verify(correct message) = false, want true")
			}

			wrongMsg := make([]byte, 32)
			copy(wrongMsg, msg)
			wrongMsg[0] ^= 0x01
			if sk.PublicKey.Verify(wrongMsg, sig) {
				t.Fatal("Verify(wrong message) = true, want false")
			}
		})
	}
}

// TestSignDeterminism checks that signing the same message twice with
// the same key produces identical bytes (SPEC §13): both the R grind and
// the WOTS+C count grind are sequential from 0, so there's no source of
// nondeterminism in signInternal to catch here besides an actual bug
// (e.g. accidental dependence on goroutine scheduling in the parallel
// leaf generation).
func TestSignDeterminism(t *testing.T) {
	sk, err := GenerateKey(C11)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	msg := make([]byte, 32)
	for i := range msg {
		msg[i] = byte(0xAA)
	}

	sig1, err := sk.Sign(msg)
	if err != nil {
		t.Fatalf("Sign #1: %v", err)
	}
	sig2, err := sk.Sign(msg)
	if err != nil {
		t.Fatalf("Sign #2: %v", err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Fatal("signing the same message twice produced different bytes")
	}
}

// TestSignerMatchesPrivateKey checks that Signer.Sign (which caches the
// top-layer subtree) produces byte-identical output to PrivateKey.Sign
// for two different messages under the same C11 key.
func TestSignerMatchesPrivateKey(t *testing.T) {
	sk, err := GenerateKey(C11)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := NewSigner(sk)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	msgs := [][]byte{
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
	}
	for _, msg := range msgs {
		direct, err := sk.Sign(msg)
		if err != nil {
			t.Fatalf("PrivateKey.Sign: %v", err)
		}
		cached, err := signer.Sign(msg)
		if err != nil {
			t.Fatalf("Signer.Sign: %v", err)
		}
		if !bytes.Equal(direct, cached) {
			t.Fatalf("Signer.Sign output differs from PrivateKey.Sign for msg %x", msg)
		}
		if !sk.PublicKey.Verify(msg, cached) {
			t.Fatalf("Signer.Sign output does not verify for msg %x", msg)
		}
	}
}

// TestSignInvalidMessageLength checks that both Sign entry points reject
// a message that isn't exactly 32 bytes with ErrInvalidMessageLength.
func TestSignInvalidMessageLength(t *testing.T) {
	sk, err := GenerateKey(C11)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := NewSigner(sk)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	for _, n := range []int{0, 16, 31, 33, 64} {
		msg := make([]byte, n)
		if _, err := sk.Sign(msg); !errors.Is(err, ErrInvalidMessageLength) {
			t.Errorf("PrivateKey.Sign(len=%d) error = %v, want errors.Is(..., ErrInvalidMessageLength)", n, err)
		}
		if _, err := signer.Sign(msg); !errors.Is(err, ErrInvalidMessageLength) {
			t.Errorf("Signer.Sign(len=%d) error = %v, want errors.Is(..., ErrInvalidMessageLength)", n, err)
		}
	}
}
