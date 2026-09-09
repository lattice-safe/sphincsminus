package sphincsminus

import (
	"context"
	"crypto/rand"
	"fmt"
)

// PublicKey is a SPHINCS⁻ public key for a given Params: a 16-byte
// tweakable-hash seed and a 16-byte hypertree root (SPEC §3).
//
// A *PublicKey is safe for concurrent use: Verify never mutates the
// receiver or any package-level state, so the same *PublicKey may be
// shared across any number of goroutines calling Verify concurrently.
type PublicKey struct {
	Params *Params
	Seed   [16]byte
	Root   [16]byte
}

// Bytes encodes the public key as the 32-byte wire form Seed‖Root
// (SPEC §3).
func (pk *PublicKey) Bytes() []byte {
	out := make([]byte, 32)
	copy(out[0:16], pk.Seed[:])
	copy(out[16:32], pk.Root[:])
	return out
}

// ParsePublicKey decodes the 32-byte wire form Seed‖Root produced by
// Bytes. It never panics on malformed input, however short or long.
func ParsePublicKey(p *Params, b []byte) (*PublicKey, error) {
	if len(b) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes, want 32", ErrInvalidPublicKey, len(b))
	}
	pk := &PublicKey{Params: p}
	copy(pk.Seed[:], b[0:16])
	copy(pk.Root[:], b[16:32])
	return pk, nil
}

// SeedWord returns Seed top-aligned in a 32-byte N_MASK word, matching
// the on-chain bytes32 pkSeed encoding (SPEC §3).
func (pk *PublicKey) SeedWord() [32]byte {
	var w [32]byte
	copy(w[:16], pk.Seed[:])
	return w
}

// RootWord returns Root top-aligned in a 32-byte N_MASK word, matching
// the on-chain bytes32 pkRoot encoding (SPEC §3).
func (pk *PublicKey) RootWord() [32]byte {
	var w [32]byte
	copy(w[:16], pk.Root[:])
	return w
}

// Verify checks sig against msg for this public key. It is a thin
// wrapper around the package-level Verify function.
func (pk *PublicKey) Verify(msg, sig []byte) bool {
	return Verify(pk.Params, pk.Seed, pk.Root, msg, sig)
}

// PrivateKey is a SPHINCS⁻ private key: the 32-byte signer secret plus
// its corresponding PublicKey (SPEC §3).
//
// PrivateKey.Sign/SignContext are safe for concurrent use: signing has
// no shared mutable state (every call works on its own local copies of
// the seeds and builds its own subtrees from scratch), so the same
// *PrivateKey may be used to sign different messages concurrently from
// multiple goroutines. The one exception is Zeroize, which mutates
// SkSeed in place: it must not be called concurrently with Sign/
// SignContext (or with another Zeroize) on the same key — callers that
// want to retire a key must first ensure no signing call on it is still
// in flight.
type PrivateKey struct {
	Params *Params
	SkSeed [32]byte
	PublicKey

	// zeroized records whether Zeroize has been called. Once true,
	// Sign/SignContext refuse to run (returning ErrInvalidPrivateKey)
	// rather than silently signing with an all-zero SkSeed, which would
	// produce a signature that looks superficially well-formed but
	// verifies under a different (and never intentionally generated)
	// key.
	zeroized bool
}

// Bytes encodes the private key as the 64-byte wire form
// SkSeed‖Seed‖Root (SPEC §3).
func (sk *PrivateKey) Bytes() []byte {
	out := make([]byte, 64)
	copy(out[0:32], sk.SkSeed[:])
	copy(out[32:48], sk.Seed[:])
	copy(out[48:64], sk.Root[:])
	return out
}

// ParsePrivateKey decodes the 64-byte wire form SkSeed‖Seed‖Root produced
// by Bytes. It never panics on malformed input, however short or long.
func ParsePrivateKey(p *Params, b []byte) (*PrivateKey, error) {
	if len(b) != 64 {
		return nil, fmt.Errorf("%w: got %d bytes, want 64", ErrInvalidPrivateKey, len(b))
	}
	sk := &PrivateKey{Params: p}
	copy(sk.SkSeed[:], b[0:32])
	sk.PublicKey.Params = p
	copy(sk.PublicKey.Seed[:], b[32:48])
	copy(sk.PublicKey.Root[:], b[48:64])
	return sk, nil
}

// Zeroize overwrites the secret seed with zeros and marks sk so that any
// later Sign/SignContext call fails with ErrInvalidPrivateKey instead of
// silently signing with the now-zeroed (and never intentionally
// generated) SkSeed. Callers that hold a PrivateKey past its useful
// lifetime should call this where practical (SPEC §13); it is not a
// substitute for proper secret-handling discipline (e.g. avoiding
// secrets in swappable memory), which is outside what a pure-Go library
// can guarantee. Zeroize must not be called concurrently with Sign/
// SignContext (or with another Zeroize) on the same key.
func (sk *PrivateKey) Zeroize() {
	for i := range sk.SkSeed {
		sk.SkSeed[i] = 0
	}
	sk.zeroized = true
}

// NewPrivateKeyFromSeeds builds a PrivateKey from an explicit skSeed and
// pkSeed, computing pkRoot as the root of the top-layer subtree (layer =
// d-1, tree = 0, SPEC §3/§8/§10). Unlike GenerateKey, the seeds are
// supplied by the caller rather than freshly sampled; this is the shared
// primitive behind both DeriveKeyReference (SPEC §3.2) and any future
// caller that already has seeds from elsewhere (e.g. NIST-style KATs).
func NewPrivateKeyFromSeeds(p *Params, skSeed [32]byte, pkSeed [16]byte) (*PrivateKey, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	var pkSeedW, skSeedW word
	copy(pkSeedW[:16], pkSeed[:])
	copy(skSeedW[:], skSeed[:])

	// context.Background() never cancels, so this can only ever return a
	// nil error; NewPrivateKeyFromSeeds itself takes no ctx (key
	// derivation is not in the set of long-running operations this
	// package's ctx support targets — only signing is), so there is
	// nothing to propagate a cancellation from.
	root, err := subtreeRoot(context.Background(), p, pkSeedW, skSeedW, uint32(p.D-1), 0)
	if err != nil {
		return nil, err
	}

	sk := &PrivateKey{Params: p, SkSeed: skSeed}
	sk.PublicKey.Params = p
	sk.PublicKey.Seed = pkSeed
	copy(sk.PublicKey.Root[:], root[:16])
	return sk, nil
}

// GenerateKey generates a fresh random SPHINCS⁻ private key for
// parameter set p using crypto/rand (SPEC §3.1): a 32-byte skSeed and a
// 16-byte pkSeed, then computes pkRoot as the root of the top-layer
// subtree. This is the Go-native key generation path; it does not match
// the reference Rust/Python signers' derivation (that's
// DeriveKeyReference, for interop/test-vector use only).
func GenerateKey(p *Params) (*PrivateKey, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	var skSeed [32]byte
	if _, err := rand.Read(skSeed[:]); err != nil {
		return nil, err
	}
	var pkSeedRand [16]byte
	if _, err := rand.Read(pkSeedRand[:]); err != nil {
		return nil, err
	}

	return NewPrivateKeyFromSeeds(p, skSeed, pkSeedRand)
}

// DeriveKeyReference derives a SPHINCS⁻ private key from 32 bytes of
// material the same way the reference Rust/Python signers do (SPEC
// §3.2): entropy = keccak256("sphincs_signer_v1" ‖ material), pkSeed =
// maskN(keccak256("pk_seed" ‖ entropy)), skSeed = keccak256("sk_seed" ‖
// entropy). This exists purely for cross-validation against
// testdata/vectors/*.json and other reference-signer interop; ordinary
// callers should use GenerateKey instead.
func DeriveKeyReference(p *Params, material [32]byte) (*PrivateKey, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	pkSeedW, skSeedW := deriveReferenceSeeds(material)
	var pkSeed16 [16]byte
	copy(pkSeed16[:], pkSeedW[:16])

	return NewPrivateKeyFromSeeds(p, skSeedW, pkSeed16)
}

// Sign produces a deterministic SPHINCS⁻ signature over msg, which must
// be exactly 32 bytes (SPEC §1: the message is always an EVM hash).
// Signing the same message twice with the same key always yields
// byte-identical output (SPEC §13): the R-grind and WOTS+C count-grind
// loops are both seeded and searched deterministically from 0. Callers
// that will sign more than once with the same key should prefer Signer,
// which caches the (otherwise redundantly rebuilt) top-layer hypertree
// subtree across calls but is required to produce byte-identical output
// to Sign. Sign is equivalent to SignContext(context.Background(), msg).
func (sk *PrivateKey) Sign(msg []byte) ([]byte, error) {
	return sk.SignContext(context.Background(), msg)
}

// SignContext behaves exactly like Sign, except that it also honors ctx:
// if ctx is canceled or its deadline expires before signing completes,
// SignContext returns promptly with a wrapped ctx.Err() rather than
// continuing to grind R or build hypertree subtrees for however many
// seconds a full sign might otherwise take (a C13 sign is a
// multi-second operation; see BenchmarkSignC13). The ctx.Err() checks
// threaded through signing are coarse-grained (never per hash), so
// signing with an uncancelled ctx — including the ctx == nil case, which
// is treated as context.Background() rather than panicking — produces
// byte-identical output to Sign for the same key and message. A nil sk
// or one that has been Zeroize()'d returns ErrInvalidPrivateKey rather
// than panicking or signing with a zeroed seed.
func (sk *PrivateKey) SignContext(ctx context.Context, msg []byte) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if sk == nil {
		return nil, ErrInvalidPrivateKey
	}
	if sk.zeroized {
		return nil, fmt.Errorf("%w: key has been zeroized", ErrInvalidPrivateKey)
	}
	if err := sk.Params.Validate(); err != nil {
		return nil, err
	}
	if len(msg) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes, want 32", ErrInvalidMessageLength, len(msg))
	}
	var msgArr [32]byte
	copy(msgArr[:], msg)

	var pkSeedW, pkRootW, skSeedW word
	copy(pkSeedW[:16], sk.PublicKey.Seed[:])
	copy(pkRootW[:16], sk.PublicKey.Root[:])
	copy(skSeedW[:], sk.SkSeed[:])
	defer func() {
		for i := range skSeedW {
			skSeedW[i] = 0
		}
	}()

	return signInternal(ctx, sk.Params, pkSeedW, pkRootW, skSeedW, msgArr, nil)
}

// Signer wraps a PrivateKey with a precomputed cache of its top-layer
// hypertree subtree (layer = d-1, tree = 0), which SPEC §10 notes is the
// same for every message under a given key (idxTree is always 0 after
// the last shift, since k*a+h bits are consumed and h = d*sh). Building
// that subtree is one of the more expensive parts of signing (2^sh
// WOTS+C public keys), so a Signer amortizes it across repeated Sign
// calls instead of rebuilding it every time as PrivateKey.Sign does.
// Signer.Sign is required to produce byte-identical output to
// sk.Sign(msg) for the same key and message.
//
// A Signer holds only its cached subtree (whose levels are public node
// values, never mutated after NewSigner builds them) plus the
// *PrivateKey it wraps, so Signer.Sign/SignContext inherit
// PrivateKey.Sign's concurrency-safety: the same *Signer may be used
// from multiple goroutines to sign different messages concurrently. As
// with PrivateKey, Zeroize must not be called concurrently with a
// Sign/SignContext still in flight on the same Signer.
type Signer struct {
	sk    *PrivateKey
	cache *subtreeCache
}

// NewSigner builds a Signer for sk, eagerly computing and caching its
// top-layer subtree (layer = d-1, tree = 0).
func NewSigner(sk *PrivateKey) (*Signer, error) {
	if sk == nil {
		return nil, ErrInvalidPrivateKey
	}
	p := sk.Params
	if err := p.Validate(); err != nil {
		return nil, err
	}

	var pkSeedW, skSeedW word
	copy(pkSeedW[:16], sk.PublicKey.Seed[:])
	copy(skSeedW[:], sk.SkSeed[:])

	layer := uint32(p.D - 1)
	// context.Background() never cancels, so this can only ever return a
	// nil error (NewSigner takes no ctx: building the cache is a
	// one-time setup cost, not part of the per-Sign-call ctx support).
	levels, err := buildSubtree(context.Background(), p, pkSeedW, skSeedW, layer, 0)
	if err != nil {
		return nil, err
	}

	return &Signer{
		sk:    sk,
		cache: &subtreeCache{layer: layer, tree: 0, levels: levels},
	}, nil
}

// Zeroize zeroizes the PrivateKey this Signer wraps (PrivateKey.Zeroize):
// after this call, s.Sign/SignContext return ErrInvalidPrivateKey. The
// cached subtree (s.cache) holds only public node values, so there is
// nothing else in a Signer that needs scrubbing. Zeroize must not be
// called concurrently with a Sign/SignContext still in flight on s.
func (s *Signer) Zeroize() {
	if s == nil || s.sk == nil {
		return
	}
	s.sk.Zeroize()
}

// Sign produces a deterministic SPHINCS⁻ signature over msg, exactly as
// sk.Sign(msg) would (byte-identical output), but reuses the cached
// top-layer subtree computed by NewSigner instead of rebuilding it. Sign
// is equivalent to SignContext(context.Background(), msg).
func (s *Signer) Sign(msg []byte) ([]byte, error) {
	return s.SignContext(context.Background(), msg)
}

// SignContext behaves exactly like Sign, except that it also honors ctx
// (see PrivateKey.SignContext for the cancellation/determinism
// contract, which applies identically here): a nil ctx is treated as
// context.Background(), and a nil Signer, a Signer wrapping a nil
// PrivateKey, or one whose PrivateKey has been Zeroize()'d all return
// ErrInvalidPrivateKey rather than panicking.
func (s *Signer) SignContext(ctx context.Context, msg []byte) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil || s.sk == nil {
		return nil, ErrInvalidPrivateKey
	}
	sk := s.sk
	if sk.zeroized {
		return nil, fmt.Errorf("%w: key has been zeroized", ErrInvalidPrivateKey)
	}
	p := sk.Params
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if len(msg) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes, want 32", ErrInvalidMessageLength, len(msg))
	}
	var msgArr [32]byte
	copy(msgArr[:], msg)

	var pkSeedW, pkRootW, skSeedW word
	copy(pkSeedW[:16], sk.PublicKey.Seed[:])
	copy(pkRootW[:16], sk.PublicKey.Root[:])
	copy(skSeedW[:], sk.SkSeed[:])
	defer func() {
		for i := range skSeedW {
			skSeedW[i] = 0
		}
	}()

	return signInternal(ctx, p, pkSeedW, pkRootW, skSeedW, msgArr, s.cache)
}
