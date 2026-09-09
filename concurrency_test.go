package sphincsminus

import (
	"bytes"
	"sync"
	"testing"
)

// TestSignerConcurrentSign checks that Signer.Sign, called concurrently
// from multiple goroutines on distinct messages, produces exactly the
// same bytes as PrivateKey.Sign run sequentially. Signer's whole point
// (keys.go) is caching the top-layer hypertree subtree across calls; this
// test exists to catch any data race on that cache (or on shared
// package-level state such as the keccak hasher pool, keccak.go) that
// could make concurrent signing nondeterministic or corrupt. Run with
// `go test -race` (see CLAUDE.md) for this to be meaningful. C11 is used
// so the test runs quickly.
func TestSignerConcurrentSign(t *testing.T) {
	sk, err := GenerateKey(C11)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := NewSigner(sk)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	const numGoroutines = 4
	msgs := make([][]byte, numGoroutines)
	for i := range msgs {
		m := make([]byte, 32)
		for j := range m {
			m[j] = byte(i*17 + j)
		}
		msgs[i] = m
	}

	// Sequential baseline: PrivateKey.Sign, one call at a time, no
	// caching.
	want := make([][]byte, numGoroutines)
	for i, m := range msgs {
		sig, err := sk.Sign(m)
		if err != nil {
			t.Fatalf("sequential Sign[%d]: %v", i, err)
		}
		want[i] = sig
	}

	// Concurrent: Signer.Sign, all goroutines sharing the same cached
	// top-layer subtree.
	got := make([][]byte, numGoroutines)
	var wg sync.WaitGroup
	for i, m := range msgs {
		wg.Add(1)
		go func(i int, m []byte) {
			defer wg.Done()
			sig, err := signer.Sign(m)
			if err != nil {
				t.Errorf("concurrent Signer.Sign[%d]: %v", i, err)
				return
			}
			got[i] = sig
		}(i, m)
	}
	wg.Wait()

	for i := range msgs {
		if got[i] == nil {
			continue // already reported via t.Errorf above
		}
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("goroutine %d: Signer.Sign output differs from sequential PrivateKey.Sign\nconcurrent: %x\nsequential: %x", i, got[i], want[i])
		}
		if !sk.PublicKey.Verify(msgs[i], got[i]) {
			t.Errorf("goroutine %d: concurrently produced signature does not verify", i)
		}
	}
}
