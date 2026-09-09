package sphincsminus

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// TestSignOnZeroizedKeyFails checks that PrivateKey.Sign/SignContext on a
// zeroized key return ErrInvalidPrivateKey instead of silently signing
// with the now-all-zero SkSeed (which would produce a signature that
// looks well-formed but doesn't correspond to any key the caller ever
// intentionally generated).
func TestSignOnZeroizedKeyFails(t *testing.T) {
	sk, err := GenerateKey(C11)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg := bytes.Repeat([]byte{0x11}, 32)

	// Sanity: the key can sign before being zeroized.
	if _, err := sk.Sign(msg); err != nil {
		t.Fatalf("Sign before Zeroize: %v", err)
	}

	sk.Zeroize()

	if sig, err := sk.Sign(msg); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Errorf("Sign after Zeroize: err = %v (sig=%x), want errors.Is(..., ErrInvalidPrivateKey)", err, sig)
	}
	if sig, err := sk.SignContext(context.Background(), msg); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Errorf("SignContext after Zeroize: err = %v (sig=%x), want errors.Is(..., ErrInvalidPrivateKey)", err, sig)
	}
}

// TestSignerZeroizeClearsKeyAndBlocksSign checks that (*Signer).Zeroize
// clears the wrapped PrivateKey's SkSeed and makes subsequent Sign/
// SignContext calls fail with ErrInvalidPrivateKey.
func TestSignerZeroizeClearsKeyAndBlocksSign(t *testing.T) {
	sk, err := GenerateKey(C11)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := NewSigner(sk)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	msg := bytes.Repeat([]byte{0x22}, 32)
	if _, err := signer.Sign(msg); err != nil {
		t.Fatalf("Sign before Zeroize: %v", err)
	}

	signer.Zeroize()

	var zero [32]byte
	if sk.SkSeed != zero {
		t.Error("Signer.Zeroize did not clear the wrapped PrivateKey's SkSeed")
	}

	if sig, err := signer.Sign(msg); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Errorf("Signer.Sign after Zeroize: err = %v (sig=%x), want errors.Is(..., ErrInvalidPrivateKey)", err, sig)
	}
	if sig, err := signer.SignContext(context.Background(), msg); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Errorf("Signer.SignContext after Zeroize: err = %v (sig=%x), want errors.Is(..., ErrInvalidPrivateKey)", err, sig)
	}
}

// TestSignZeroizesTemporaries is the Phase 4 hardening task's pinning
// test for SPEC §13's zeroization guidance: (*Signer).Zeroize clears the
// wrapped key's SkSeed, and the cleaner, checkable semantic this package
// picked over "produces an unverifiable signature" is that a subsequent
// Sign/SignContext call fails outright with ErrInvalidPrivateKey (see
// PrivateKey.zeroized) rather than silently signing with an all-zero
// seed nobody ever intentionally generated.
func TestSignZeroizesTemporaries(t *testing.T) {
	sk, err := GenerateKey(C13)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := NewSigner(sk)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	signer.Zeroize()

	var zero [32]byte
	if sk.SkSeed != zero {
		t.Fatal("Signer.Zeroize did not clear sk.SkSeed")
	}

	msg := bytes.Repeat([]byte{0x33}, 32)
	if sig, err := signer.Sign(msg); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Errorf("Sign after Zeroize: err = %v (sig=%x), want errors.Is(..., ErrInvalidPrivateKey)", err, sig)
	}
}

// TestSignerZeroizeNilSafe checks that (*Signer).Zeroize on a nil Signer,
// or one wrapping a nil PrivateKey, does not panic.
func TestSignerZeroizeNilSafe(t *testing.T) {
	var nilSigner *Signer
	nilSigner.Zeroize() // must not panic

	empty := &Signer{}
	empty.Zeroize() // must not panic (s.sk == nil)
}
