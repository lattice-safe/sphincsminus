package sphincsminus

import (
	"bytes"
	"testing"
)

// TestGenerateKeyProducesUsableKey checks that GenerateKey (SPEC §3.1's
// crypto/rand path) yields a key that Sign/Verify round-trips, and that
// two calls produce different keys (i.e. it isn't accidentally
// deterministic).
func TestGenerateKeyProducesUsableKey(t *testing.T) {
	sk1, err := GenerateKey(C11)
	if err != nil {
		t.Fatalf("GenerateKey #1: %v", err)
	}
	sk2, err := GenerateKey(C11)
	if err != nil {
		t.Fatalf("GenerateKey #2: %v", err)
	}
	if sk1.SkSeed == sk2.SkSeed {
		t.Fatal("two GenerateKey calls produced the same skSeed")
	}
	if sk1.PublicKey.Seed == sk2.PublicKey.Seed {
		t.Fatal("two GenerateKey calls produced the same pkSeed")
	}

	msg := bytes.Repeat([]byte{0x42}, 32)
	sig, err := sk1.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !sk1.PublicKey.Verify(msg, sig) {
		t.Fatal("Verify(own key) = false, want true")
	}
	if sk2.PublicKey.Verify(msg, sig) {
		t.Fatal("Verify(other key's signature) = true, want false")
	}
}

// TestGenerateKeyInvalidParams checks that GenerateKey propagates
// Params.Validate()'s error instead of panicking or silently producing a
// broken key.
func TestGenerateKeyInvalidParams(t *testing.T) {
	if _, err := GenerateKey(nil); err == nil {
		t.Fatal("GenerateKey(nil) = nil error, want an error")
	}
	bad := &Params{Name: "bad", N: 8, H: 16, D: 2, A: 11, K: 13, W: 8, LogW: 3, L: 43, TargetSum: 203}
	if _, err := GenerateKey(bad); err == nil {
		t.Fatal("GenerateKey(invalid N) = nil error, want an error")
	}
}

// TestNewPrivateKeyFromSeedsRoundtrip checks that NewPrivateKeyFromSeeds
// followed by Bytes()/ParsePrivateKey round-trips exactly, and that the
// computed pkRoot is stable (calling it twice with the same seeds gives
// the same root).
func TestNewPrivateKeyFromSeedsRoundtrip(t *testing.T) {
	var skSeed [32]byte
	var pkSeed [16]byte
	for i := range skSeed {
		skSeed[i] = byte(i + 1)
	}
	for i := range pkSeed {
		pkSeed[i] = byte(0xF0 + i)
	}

	sk1, err := NewPrivateKeyFromSeeds(C11, skSeed, pkSeed)
	if err != nil {
		t.Fatalf("NewPrivateKeyFromSeeds #1: %v", err)
	}
	sk2, err := NewPrivateKeyFromSeeds(C11, skSeed, pkSeed)
	if err != nil {
		t.Fatalf("NewPrivateKeyFromSeeds #2: %v", err)
	}
	if sk1.PublicKey.Root != sk2.PublicKey.Root {
		t.Fatal("NewPrivateKeyFromSeeds computed a different root for the same seeds")
	}

	encoded := sk1.Bytes()
	if len(encoded) != 64 {
		t.Fatalf("Bytes() len = %d, want 64", len(encoded))
	}

	parsed, err := ParsePrivateKey(C11, encoded)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	if parsed.SkSeed != sk1.SkSeed {
		t.Fatal("round-tripped SkSeed mismatch")
	}
	if parsed.PublicKey.Seed != sk1.PublicKey.Seed {
		t.Fatal("round-tripped pkSeed mismatch")
	}
	if parsed.PublicKey.Root != sk1.PublicKey.Root {
		t.Fatal("round-tripped pkRoot mismatch")
	}

	// The round-tripped key must also sign/verify correctly.
	msg := bytes.Repeat([]byte{0x99}, 32)
	sig, err := parsed.Sign(msg)
	if err != nil {
		t.Fatalf("Sign on round-tripped key: %v", err)
	}
	if !parsed.PublicKey.Verify(msg, sig) {
		t.Fatal("round-tripped key: Verify = false, want true")
	}
	if !sk1.PublicKey.Verify(msg, sig) {
		t.Fatal("original key: Verify(round-tripped key's signature) = false, want true")
	}
}

// TestDeriveKeyReferenceDeterministic checks that DeriveKeyReference is a
// pure function of (params, material): calling it twice with the same
// material yields identical seeds and root.
func TestDeriveKeyReferenceDeterministic(t *testing.T) {
	var material [32]byte
	for i := range material {
		material[i] = byte(i)
	}

	sk1, err := DeriveKeyReference(C13, material)
	if err != nil {
		t.Fatalf("DeriveKeyReference #1: %v", err)
	}
	sk2, err := DeriveKeyReference(C13, material)
	if err != nil {
		t.Fatalf("DeriveKeyReference #2: %v", err)
	}
	if sk1.SkSeed != sk2.SkSeed || sk1.PublicKey.Seed != sk2.PublicKey.Seed || sk1.PublicKey.Root != sk2.PublicKey.Root {
		t.Fatal("DeriveKeyReference is not deterministic in (params, material)")
	}
}

// TestZeroize checks that Zeroize actually clears SkSeed.
func TestZeroize(t *testing.T) {
	sk, err := GenerateKey(C11)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sk.Zeroize()
	var zero [32]byte
	if sk.SkSeed != zero {
		t.Fatal("Zeroize did not clear SkSeed")
	}
}

// TestZeroizeDoesNotTouchPublicKey checks that Zeroize only clears the
// secret seed, leaving the (public) Params/Seed/Root fields intact so a
// zeroized key can still be used to identify (though no longer to sign
// for) its owner.
func TestZeroizeDoesNotTouchPublicKey(t *testing.T) {
	sk, err := GenerateKey(C11)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	wantSeed := sk.PublicKey.Seed
	wantRoot := sk.PublicKey.Root
	sk.Zeroize()
	if sk.PublicKey.Seed != wantSeed || sk.PublicKey.Root != wantRoot {
		t.Fatal("Zeroize disturbed the public key material")
	}
}

// TestPublicKeyBytesRoundtrip checks PublicKey.Bytes/ParsePublicKey
// round-trip exactly (SPEC §3): Seed‖Root, 32 bytes.
func TestPublicKeyBytesRoundtrip(t *testing.T) {
	sk, err := GenerateKey(C11)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pk := &sk.PublicKey

	encoded := pk.Bytes()
	if len(encoded) != 32 {
		t.Fatalf("PublicKey.Bytes() len = %d, want 32", len(encoded))
	}
	if !bytes.Equal(encoded[0:16], pk.Seed[:]) {
		t.Error("PublicKey.Bytes()[0:16] != Seed")
	}
	if !bytes.Equal(encoded[16:32], pk.Root[:]) {
		t.Error("PublicKey.Bytes()[16:32] != Root")
	}

	parsed, err := ParsePublicKey(C11, encoded)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if parsed.Seed != pk.Seed || parsed.Root != pk.Root || parsed.Params != C11 {
		t.Fatalf("ParsePublicKey(pk.Bytes()) = %+v, want Seed=%x Root=%x Params=C11", parsed, pk.Seed, pk.Root)
	}

	// The parsed key must verify signatures from the original key.
	msg := bytes.Repeat([]byte{0x37}, 32)
	sig, err := sk.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !parsed.Verify(msg, sig) {
		t.Fatal("parsed PublicKey does not verify a signature made by the key it was parsed from")
	}
}

// TestPrivateKeyPublicKeyMatchesParsedSuffix checks that the PublicKey
// embedded in a PrivateKey equals ParsePublicKey applied to the last 32
// bytes of PrivateKey.Bytes() (SPEC §3: sk wire form is
// SkSeed‖Seed‖Root, i.e. the tail is exactly the pk wire form).
func TestPrivateKeyPublicKeyMatchesParsedSuffix(t *testing.T) {
	sk, err := GenerateKey(C13)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	skBytes := sk.Bytes()
	if len(skBytes) != 64 {
		t.Fatalf("PrivateKey.Bytes() len = %d, want 64", len(skBytes))
	}

	pk, err := ParsePublicKey(C13, skBytes[32:])
	if err != nil {
		t.Fatalf("ParsePublicKey(sk.Bytes()[32:]): %v", err)
	}
	if *pk != sk.PublicKey {
		t.Fatalf("ParsePublicKey(sk.Bytes()[32:]) = %+v, want %+v", *pk, sk.PublicKey)
	}
}

// TestPublicKeySeedRootWord checks that SeedWord/RootWord return the
// 16-byte Seed/Root top-aligned in a 32-byte N_MASK word, matching the
// on-chain bytes32 encoding (SPEC §3).
func TestPublicKeySeedRootWord(t *testing.T) {
	sk, err := GenerateKey(C11)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pk := &sk.PublicKey

	seedWord := pk.SeedWord()
	if !bytes.Equal(seedWord[0:16], pk.Seed[:]) {
		t.Error("SeedWord()[0:16] != Seed")
	}
	for i := 16; i < 32; i++ {
		if seedWord[i] != 0 {
			t.Errorf("SeedWord()[%d] = %#x, want 0 (low bytes must be zero)", i, seedWord[i])
		}
	}

	rootWord := pk.RootWord()
	if !bytes.Equal(rootWord[0:16], pk.Root[:]) {
		t.Error("RootWord()[0:16] != Root")
	}
	for i := 16; i < 32; i++ {
		if rootWord[i] != 0 {
			t.Errorf("RootWord()[%d] = %#x, want 0 (low bytes must be zero)", i, rootWord[i])
		}
	}
}

// TestParsePublicKeyWrongLength checks that ParsePublicKey rejects every
// length other than exactly 32.
func TestParsePublicKeyWrongLength(t *testing.T) {
	for _, n := range []int{0, 1, 16, 31, 33, 64} {
		if _, err := ParsePublicKey(C11, make([]byte, n)); err != ErrInvalidPublicKey {
			t.Errorf("ParsePublicKey(len=%d) error = %v, want ErrInvalidPublicKey", n, err)
		}
	}
}

// TestParsePrivateKeyWrongLength checks that ParsePrivateKey rejects
// every length other than exactly 64, and that a key parsed from the
// correct length signs a message that verifies under its own public key
// (a round-trip sanity check distinct from
// TestNewPrivateKeyFromSeedsRoundtrip's, which starts from
// NewPrivateKeyFromSeeds rather than from parsing arbitrary bytes).
func TestParsePrivateKeyWrongLength(t *testing.T) {
	for _, n := range []int{0, 1, 32, 63, 65, 128} {
		if _, err := ParsePrivateKey(C11, make([]byte, n)); err != ErrInvalidPrivateKey {
			t.Errorf("ParsePrivateKey(len=%d) error = %v, want ErrInvalidPrivateKey", n, err)
		}
	}

	sk, err := GenerateKey(C11)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	parsed, err := ParsePrivateKey(C11, sk.Bytes())
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}

	msg := bytes.Repeat([]byte{0x5a}, 32)
	sig, err := parsed.Sign(msg)
	if err != nil {
		t.Fatalf("Sign on parsed key: %v", err)
	}
	if !parsed.PublicKey.Verify(msg, sig) {
		t.Fatal("parsed PrivateKey's Sign output does not verify under its own PublicKey")
	}
}

// TestNewPrivateKeyFromSeedsInvalidParams checks that
// NewPrivateKeyFromSeeds propagates Params.Validate()'s error instead of
// silently producing a broken key.
func TestNewPrivateKeyFromSeedsInvalidParams(t *testing.T) {
	var skSeed [32]byte
	var pkSeed [16]byte
	if _, err := NewPrivateKeyFromSeeds(nil, skSeed, pkSeed); err == nil {
		t.Fatal("NewPrivateKeyFromSeeds(nil params, ...) = nil error, want an error")
	}
	bad := &Params{Name: "bad", N: 8, H: 16, D: 2, A: 11, K: 13, W: 8, LogW: 3, L: 43, TargetSum: 203}
	if _, err := NewPrivateKeyFromSeeds(bad, skSeed, pkSeed); err == nil {
		t.Fatal("NewPrivateKeyFromSeeds(invalid params, ...) = nil error, want an error")
	}
}

// TestDeriveKeyReferenceInvalidParams checks that DeriveKeyReference
// propagates Params.Validate()'s error instead of silently producing a
// broken key.
func TestDeriveKeyReferenceInvalidParams(t *testing.T) {
	var material [32]byte
	if _, err := DeriveKeyReference(nil, material); err == nil {
		t.Fatal("DeriveKeyReference(nil params, ...) = nil error, want an error")
	}
	bad := &Params{Name: "bad", N: 16, H: 16, D: 0, A: 11, K: 13, W: 8, LogW: 3, L: 43, TargetSum: 203}
	if _, err := DeriveKeyReference(bad, material); err == nil {
		t.Fatal("DeriveKeyReference(invalid params, ...) = nil error, want an error")
	}
}

// TestNewSignerInvalid checks that NewSigner rejects a nil PrivateKey and
// propagates Params.Validate()'s error for a key with an invalid
// parameter set, instead of panicking or silently building a broken
// cache.
func TestNewSignerInvalid(t *testing.T) {
	if _, err := NewSigner(nil); err == nil {
		t.Fatal("NewSigner(nil) = nil error, want an error")
	}

	bad := &Params{Name: "bad", N: 16, H: 16, D: 0, A: 11, K: 13, W: 8, LogW: 3, L: 43, TargetSum: 203}
	sk := &PrivateKey{Params: bad}
	if _, err := NewSigner(sk); err == nil {
		t.Fatal("NewSigner(key with invalid params) = nil error, want an error")
	}
}
