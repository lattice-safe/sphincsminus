package sphincsminus

import "testing"

// brokenParamsForPanicTest returns a battery of deliberately malformed
// *Params values (Phase 4 hardening task): each one must fail
// Params.Validate(), and every public entry point that accepts a
// caller-supplied *Params (Verify, PublicKey.Verify, PrivateKey.Sign,
// Signer construction) must reject it with false/an error instead of
// panicking, no matter how its internal index/shift arithmetic would
// misbehave if the bad shape were ever actually used to index a slice.
func brokenParamsForPanicTest() []*Params {
	return []*Params{
		{}, // zero struct: N=0, D=0, A=0, K=0, H=0, L=0, ...
		{Name: "A=0", N: 16, H: 22, D: 2, A: 0, K: 7, W: 8, LogW: 3, L: 43, TargetSum: 208},
		{Name: "A_too_big", N: 16, H: 22, D: 2, A: 200, K: 7, W: 8, LogW: 3, L: 43, TargetSum: 208},
		{Name: "K=0", N: 16, H: 22, D: 2, A: 19, K: 0, W: 8, LogW: 3, L: 43, TargetSum: 208},
		{Name: "K=1", N: 16, H: 22, D: 2, A: 19, K: 1, W: 8, LogW: 3, L: 43, TargetSum: 208},
		{Name: "H=0", N: 16, H: 0, D: 2, A: 19, K: 7, W: 8, LogW: 3, L: 43, TargetSum: 208},
		{Name: "H=65", N: 16, H: 65, D: 2, A: 19, K: 7, W: 8, LogW: 3, L: 43, TargetSum: 208},
		{Name: "H_not_multiple_of_D", N: 16, H: 23, D: 2, A: 19, K: 7, W: 8, LogW: 3, L: 43, TargetSum: 208},
		{Name: "L=42", N: 16, H: 22, D: 2, A: 19, K: 7, W: 8, LogW: 3, L: 42, TargetSum: 208},
		{Name: "N=32", N: 32, H: 22, D: 2, A: 19, K: 7, W: 8, LogW: 3, L: 43, TargetSum: 208},
		{Name: "sh=33", N: 16, H: 33, D: 1, A: 19, K: 7, W: 8, LogW: 3, L: 43, TargetSum: 208},
		{Name: "D=0", N: 16, H: 22, D: 0, A: 19, K: 7, W: 8, LogW: 3, L: 43, TargetSum: 208},
		{Name: "D=negative", N: 16, H: 22, D: -1, A: 19, K: 7, W: 8, LogW: 3, L: 43, TargetSum: 208},
		{Name: "K*A+H>256", N: 16, H: 22, D: 2, A: 19, K: 100, W: 8, LogW: 3, L: 43, TargetSum: 208},
		{Name: "W_wrong", N: 16, H: 22, D: 2, A: 19, K: 7, W: 16, LogW: 4, L: 43, TargetSum: 208},
	}
}

// paramsName returns p.Name, or a stand-in for the zero-struct case whose
// Name field is itself the empty string.
func paramsName(p *Params) string {
	if p.Name == "" {
		return "zero-struct"
	}
	return p.Name
}

// mustNotPanic runs fn and turns any panic into a test failure via
// recover, instead of letting it crash the test binary -- this is the
// mechanism the Phase 4 hardening task asks for: a battery of
// deliberately broken Params must never panic anywhere in the public
// API, and this helper is how these tests prove it.
func mustNotPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: panicked: %v", name, r)
		}
	}()
	fn()
}

// TestBrokenParamsNoPanicVerify checks that Verify and PublicKey.Verify
// never panic when handed one of brokenParamsForPanicTest's malformed
// Params, and that they reject (return false) rather than accidentally
// accepting.
func TestBrokenParamsNoPanicVerify(t *testing.T) {
	var pkSeed, pkRoot [16]byte
	msg := make([]byte, 32)
	// Deliberately not the right length for any of these (all malformed)
	// Params: exercises the internal index arithmetic that a valid-length
	// signature would otherwise reach.
	sig := make([]byte, 4096)

	for _, p := range brokenParamsForPanicTest() {
		p := p
		name := paramsName(p)
		t.Run(name, func(t *testing.T) {
			if err := p.Validate(); err == nil {
				t.Fatalf("%s: Validate() = nil, want an error (test assumption violated)", name)
			}

			mustNotPanic(t, name, func() {
				if Verify(p, pkSeed, pkRoot, msg, sig) {
					t.Errorf("%s: Verify(...) = true, want false", name)
				}
			})

			pk := &PublicKey{Params: p, Seed: pkSeed, Root: pkRoot}
			mustNotPanic(t, name, func() {
				if pk.Verify(msg, sig) {
					t.Errorf("%s: PublicKey.Verify(...) = true, want false", name)
				}
			})
		})
	}
}

// TestBrokenParamsNoPanicSign checks that PrivateKey.Sign/SignContext and
// NewSigner never panic on a broken Params and instead return an error.
func TestBrokenParamsNoPanicSign(t *testing.T) {
	msg := make([]byte, 32)

	for _, p := range brokenParamsForPanicTest() {
		p := p
		name := paramsName(p)
		t.Run(name, func(t *testing.T) {
			sk := &PrivateKey{Params: p}
			mustNotPanic(t, name, func() {
				if sig, err := sk.Sign(msg); err == nil {
					t.Errorf("%s: PrivateKey.Sign(...) = (%x, nil), want an error", name, sig)
				}
			})

			mustNotPanic(t, name, func() {
				if _, err := NewSigner(sk); err == nil {
					t.Errorf("%s: NewSigner(...) = nil error, want an error", name)
				}
			})

			mustNotPanic(t, name, func() {
				if _, err := GenerateKey(p); err == nil {
					t.Errorf("%s: GenerateKey(...) = nil error, want an error", name)
				}
			})
		})
	}
}
