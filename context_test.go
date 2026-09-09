package sphincsminus

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"
)

// goroutineBaseline runs a GC (to reap any goroutines that have already
// exited but not yet been counted out) and returns the current goroutine
// count, for later comparison by waitForGoroutineBaseline.
func goroutineBaseline(t *testing.T) int {
	t.Helper()
	runtime.GC()
	return runtime.NumGoroutine()
}

// waitForGoroutineBaseline polls runtime.NumGoroutine() until it returns
// to at most baseline, failing the test if that doesn't happen within a
// couple of seconds. Goroutines spawned by parallelChunks notice a
// canceled ctx within one grindCheckInterval-sized sub-batch and exit on
// their own, but exiting and being reflected in runtime.NumGoroutine()
// isn't instantaneous, hence the poll instead of a single snapshot.
func waitForGoroutineBaseline(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		n := runtime.NumGoroutine()
		if n <= baseline {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("goroutine count did not return to baseline: got %d, want <= %d", n, baseline)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestSignContextCancel checks that PrivateKey.SignContext returns
// promptly with a wrapped ctx.Err() when its context is canceled partway
// through a (deliberately slow) C13 sign, and that every goroutine it
// spawned along the way (parallelChunks' FORS/WOTS leaf-generation
// workers) has exited by the time it returns -- no goroutine leaks (SPEC
// §13 / Phase 4 hardening task). A full, uncancelled C13 sign takes
// several seconds (see BenchmarkSignC13); canceling after 50ms and
// asserting a return within ~1s is therefore a meaningful test of the
// ctx.Err() checks actually firing well before the sign would otherwise
// finish on its own, not merely happening to finish first.
func TestSignContextCancel(t *testing.T) {
	sk, err := GenerateKey(C13)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	baseline := goroutineBaseline(t)

	msg := make([]byte, 32)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	type result struct {
		sig []byte
		err error
	}
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		sig, err := sk.SignContext(ctx, msg)
		done <- result{sig, err}
	}()

	var res result
	select {
	case res = <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("SignContext did not return within 1s of its 50ms context deadline")
	}
	elapsed := time.Since(start)

	if res.err == nil {
		t.Fatalf("SignContext returned no error (sig len %d); want a context-deadline error", len(res.sig))
	}
	if !errors.Is(res.err, context.DeadlineExceeded) {
		t.Errorf("SignContext error = %v, want errors.Is(..., context.DeadlineExceeded)", res.err)
	}
	if elapsed > 1*time.Second {
		t.Errorf("SignContext took %s to return after cancellation, want well under 1s", elapsed)
	}

	waitForGoroutineBaseline(t, baseline)
}

// TestSignerSignContextCancel is TestSignContextCancel's Signer.Sign
// counterpart: canceling a Signer.SignContext call must behave
// identically (prompt return, wrapped ctx.Err(), no goroutine leak),
// since Signer.SignContext funnels through the same signInternal.
func TestSignerSignContextCancel(t *testing.T) {
	sk, err := GenerateKey(C13)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := NewSigner(sk)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	baseline := goroutineBaseline(t)

	msg := make([]byte, 32)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	type result struct {
		sig []byte
		err error
	}
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		sig, err := signer.SignContext(ctx, msg)
		done <- result{sig, err}
	}()

	var res result
	select {
	case res = <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("Signer.SignContext did not return within 1s of its 50ms context deadline")
	}
	elapsed := time.Since(start)

	if res.err == nil {
		t.Fatalf("Signer.SignContext returned no error (sig len %d); want a context-deadline error", len(res.sig))
	}
	if !errors.Is(res.err, context.DeadlineExceeded) {
		t.Errorf("Signer.SignContext error = %v, want errors.Is(..., context.DeadlineExceeded)", res.err)
	}
	if elapsed > 1*time.Second {
		t.Errorf("Signer.SignContext took %s to return after cancellation, want well under 1s", elapsed)
	}

	waitForGoroutineBaseline(t, baseline)
}

// TestSignContextAlreadyCanceled checks the simpler case of a ctx that is
// already canceled before SignContext is ever called: it must return
// immediately with a wrapped context.Canceled, never attempting so much
// as the first R-grind hash.
func TestSignContextAlreadyCanceled(t *testing.T) {
	sk, err := GenerateKey(C11)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	msg := make([]byte, 32)
	start := time.Now()
	sig, err := sk.SignContext(ctx, msg)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("SignContext(already-canceled ctx) = (%x, nil), want an error", sig)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("SignContext(already-canceled ctx) error = %v, want errors.Is(..., context.Canceled)", err)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("SignContext(already-canceled ctx) took %s, want near-instant", elapsed)
	}
}

// TestSignContextNilTreatedAsBackground checks that passing a nil
// context.Context to SignContext is treated as context.Background()
// (never cancels, never panics) rather than panicking on the first
// ctx.Err() call.
func TestSignContextNilTreatedAsBackground(t *testing.T) {
	sk, err := GenerateKey(C11)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := NewSigner(sk)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	msg := make([]byte, 32)
	// A genuinely nil context.Context, held in a variable rather than
	// passed as a literal `nil` (which would trip staticcheck's SA1012 --
	// good general advice, but this test's entire point is to pin
	// SignContext's own defensive handling of exactly that misuse).
	var nilCtx context.Context
	sig, err := sk.SignContext(nilCtx, msg)
	if err != nil {
		t.Fatalf("SignContext(nil, ...) error = %v, want nil", err)
	}
	if !sk.PublicKey.Verify(msg, sig) {
		t.Error("SignContext(nil, ...) produced a signature that does not verify")
	}

	sig2, err := signer.SignContext(nilCtx, msg)
	if err != nil {
		t.Fatalf("Signer.SignContext(nil, ...) error = %v, want nil", err)
	}
	if !sk.PublicKey.Verify(msg, sig2) {
		t.Error("Signer.SignContext(nil, ...) produced a signature that does not verify")
	}
}

// TestSignContextUncancelledMatchesSign checks that SignContext with an
// uncancelled context.Background() produces byte-identical output to
// Sign for the same key and message: threading ctx.Err() checks through
// the signer must never change which nonce/count/leaf is chosen.
func TestSignContextUncancelledMatchesSign(t *testing.T) {
	sk, err := GenerateKey(C11)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	msg := make([]byte, 32)
	for i := range msg {
		msg[i] = byte(i * 3)
	}

	want, err := sk.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got, err := sk.SignContext(context.Background(), msg)
	if err != nil {
		t.Fatalf("SignContext: %v", err)
	}
	if string(got) != string(want) {
		t.Fatal("SignContext(context.Background(), ...) differs from Sign(...)")
	}
}
