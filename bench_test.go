package sphincsminus

import (
	"crypto/rand"
	"testing"
)

// benchmarkKeygen is shared by BenchmarkKeygenC11/C13: each iteration
// generates a full fresh key (crypto/rand seeds plus the top-layer
// subtree build), so it exercises the same buildSubtree/wotsPkOnly path
// signing does for its top layer.
func benchmarkKeygen(b *testing.B, p *Params) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := GenerateKey(p); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKeygenC11(b *testing.B) { benchmarkKeygen(b, C11) }
func BenchmarkKeygenC13(b *testing.B) { benchmarkKeygen(b, C13) }

// benchmarkSign is shared by BenchmarkSignC11/C13. Key generation and
// message setup happen before b.ResetTimer() so only signInternal's cost
// (R grind, FORS trees, both hypertree layers) is measured. Note that,
// unlike a Signer, PrivateKey.Sign rebuilds every subtree layer (including
// the top one) on every call — this benchmark intentionally measures that
// full, uncached cost, since it's the one every first-time caller pays.
func benchmarkSign(b *testing.B, p *Params) {
	sk, err := GenerateKey(p)
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 32)
	if _, err := rand.Read(msg); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := sk.Sign(msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignC11(b *testing.B) { benchmarkSign(b, C11) }
func BenchmarkSignC13(b *testing.B) { benchmarkSign(b, C13) }

// benchmarkVerify is shared by BenchmarkVerifyC11/C13: one signature is
// produced up front, then verified repeatedly (Verify is deterministic
// and side-effect-free, so re-verifying the same signature is
// representative of steady-state verification cost).
func benchmarkVerify(b *testing.B, p *Params) {
	sk, err := GenerateKey(p)
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 32)
	if _, err := rand.Read(msg); err != nil {
		b.Fatal(err)
	}
	sig, err := sk.Sign(msg)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !sk.PublicKey.Verify(msg, sig) {
			b.Fatal("Verify returned false for a freshly produced signature")
		}
	}
}

func BenchmarkVerifyC11(b *testing.B) { benchmarkVerify(b, C11) }
func BenchmarkVerifyC13(b *testing.B) { benchmarkVerify(b, C13) }
