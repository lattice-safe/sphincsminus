package sphincsminus

import (
	"context"
	"errors"
	"testing"
)

// TestErrorsIsErrInvalidParams checks that every path that reports an
// invalid *Params wraps ErrInvalidParams with %w, so errors.Is(err,
// ErrInvalidParams) succeeds regardless of how much extra context (the
// parameter name, the offending field) has been layered on top.
func TestErrorsIsErrInvalidParams(t *testing.T) {
	bad := &Params{Name: "bad", N: 8}

	if err := bad.Validate(); !errors.Is(err, ErrInvalidParams) {
		t.Errorf("Params.Validate() error = %v, want errors.Is(..., ErrInvalidParams)", err)
	}
	if _, err := GenerateKey(bad); !errors.Is(err, ErrInvalidParams) {
		t.Errorf("GenerateKey(bad) error = %v, want errors.Is(..., ErrInvalidParams)", err)
	}
	if _, err := NewPrivateKeyFromSeeds(bad, [32]byte{}, [16]byte{}); !errors.Is(err, ErrInvalidParams) {
		t.Errorf("NewPrivateKeyFromSeeds(bad, ...) error = %v, want errors.Is(..., ErrInvalidParams)", err)
	}
	if _, err := DeriveKeyReference(bad, [32]byte{}); !errors.Is(err, ErrInvalidParams) {
		t.Errorf("DeriveKeyReference(bad, ...) error = %v, want errors.Is(..., ErrInvalidParams)", err)
	}
	if _, err := NewSigner(&PrivateKey{Params: bad}); !errors.Is(err, ErrInvalidParams) {
		t.Errorf("NewSigner(key with bad params) error = %v, want errors.Is(..., ErrInvalidParams)", err)
	}
	if _, err := (&PrivateKey{Params: bad}).Sign(make([]byte, 32)); !errors.Is(err, ErrInvalidParams) {
		t.Errorf("PrivateKey.Sign(bad params) error = %v, want errors.Is(..., ErrInvalidParams)", err)
	}
}

// TestErrorsIsErrInvalidPublicKey checks that ParsePublicKey's
// wrong-length error wraps ErrInvalidPublicKey.
func TestErrorsIsErrInvalidPublicKey(t *testing.T) {
	if _, err := ParsePublicKey(C11, make([]byte, 31)); !errors.Is(err, ErrInvalidPublicKey) {
		t.Errorf("ParsePublicKey(31 bytes) error = %v, want errors.Is(..., ErrInvalidPublicKey)", err)
	}
}

// TestErrorsIsErrInvalidPrivateKey checks every path that reports an
// invalid private key: ParsePrivateKey's wrong-length error, NewSigner
// on a nil key, and Sign/SignContext on a zeroized key.
func TestErrorsIsErrInvalidPrivateKey(t *testing.T) {
	if _, err := ParsePrivateKey(C11, make([]byte, 63)); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Errorf("ParsePrivateKey(63 bytes) error = %v, want errors.Is(..., ErrInvalidPrivateKey)", err)
	}
	if _, err := NewSigner(nil); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Errorf("NewSigner(nil) error = %v, want errors.Is(..., ErrInvalidPrivateKey)", err)
	}

	sk, err := GenerateKey(C11)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sk.Zeroize()
	if _, err := sk.Sign(make([]byte, 32)); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Errorf("Sign(zeroized key) error = %v, want errors.Is(..., ErrInvalidPrivateKey)", err)
	}
}

// TestErrorsIsErrInvalidMessageLength checks that both Sign entry
// points' message-length error wraps ErrInvalidMessageLength.
func TestErrorsIsErrInvalidMessageLength(t *testing.T) {
	sk, err := GenerateKey(C11)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := NewSigner(sk)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	if _, err := sk.Sign(make([]byte, 31)); !errors.Is(err, ErrInvalidMessageLength) {
		t.Errorf("PrivateKey.Sign(31 bytes) error = %v, want errors.Is(..., ErrInvalidMessageLength)", err)
	}
	if _, err := signer.Sign(make([]byte, 33)); !errors.Is(err, ErrInvalidMessageLength) {
		t.Errorf("Signer.Sign(33 bytes) error = %v, want errors.Is(..., ErrInvalidMessageLength)", err)
	}
}

// TestErrorsIsContextCanceled checks that a canceled ctx surfaces through
// SignContext as an error satisfying errors.Is(err, context.Canceled).
func TestErrorsIsContextCanceled(t *testing.T) {
	sk, err := GenerateKey(C11)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := sk.SignContext(ctx, make([]byte, 32)); !errors.Is(err, context.Canceled) {
		t.Errorf("SignContext(canceled ctx) error = %v, want errors.Is(..., context.Canceled)", err)
	}
}

// TestErrorsIsErrGrindExhausted checks that ErrGrindExhausted, the one
// grinding-loop error that is not a ctx cancellation, is returned as-is
// (and therefore trivially satisfies errors.Is against itself) rather
// than being wrapped away into something else.
func TestErrorsIsErrGrindExhausted(t *testing.T) {
	if !errors.Is(ErrGrindExhausted, ErrGrindExhausted) {
		t.Fatal("errors.Is(ErrGrindExhausted, ErrGrindExhausted) = false, want true (sanity check)")
	}
	if err := wrapSignErr(ErrGrindExhausted); !errors.Is(err, ErrGrindExhausted) {
		t.Errorf("wrapSignErr(ErrGrindExhausted) = %v, want errors.Is(..., ErrGrindExhausted)", err)
	}
}
