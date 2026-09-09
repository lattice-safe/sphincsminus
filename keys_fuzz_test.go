package sphincsminus

import (
	"bytes"
	"testing"
)

// FuzzParsePublicKey checks that ParsePublicKey never panics on any
// input length or content, and that whenever it does succeed (only ever
// for len(b)==32), re-encoding the parsed key reproduces exactly the
// bytes that were parsed (round-trip property).
func FuzzParsePublicKey(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 16))
	f.Add(make([]byte, 31))
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 33))
	f.Add(make([]byte, 64))
	if sk, err := GenerateKey(C11); err == nil {
		f.Add(sk.PublicKey.Bytes())
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		pk, err := ParsePublicKey(C11, b)
		if err != nil {
			if pk != nil {
				t.Fatalf("ParsePublicKey returned a non-nil key alongside error %v", err)
			}
			return
		}
		if len(b) != 32 {
			t.Fatalf("ParsePublicKey succeeded for len(b)=%d, want failure for any length != 32", len(b))
		}
		if got := pk.Bytes(); !bytes.Equal(got, b) {
			t.Fatalf("round-trip mismatch: parsed %x, re-encoded %x", b, got)
		}
	})
}

// FuzzParsePrivateKey is FuzzParsePublicKey's PrivateKey counterpart:
// ParsePrivateKey must never panic, and a successful parse (only ever
// for len(b)==64) must round-trip through Bytes exactly.
func FuzzParsePrivateKey(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 63))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 65))
	f.Add(make([]byte, 128))
	if sk, err := GenerateKey(C11); err == nil {
		f.Add(sk.Bytes())
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		sk, err := ParsePrivateKey(C11, b)
		if err != nil {
			if sk != nil {
				t.Fatalf("ParsePrivateKey returned a non-nil key alongside error %v", err)
			}
			return
		}
		if len(b) != 64 {
			t.Fatalf("ParsePrivateKey succeeded for len(b)=%d, want failure for any length != 64", len(b))
		}
		if got := sk.Bytes(); !bytes.Equal(got, b) {
			t.Fatalf("round-trip mismatch: parsed %x, re-encoded %x", b, got)
		}
	})
}
