package sphincsminus

import "crypto/rand"

// PublicKey is a SPHINCS⁻ public key for a given Params: a 16-byte
// tweakable-hash seed and a 16-byte hypertree root (SPEC §3).
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
// Bytes.
func ParsePublicKey(p *Params, b []byte) (*PublicKey, error) {
	if len(b) != 32 {
		return nil, ErrInvalidPublicKey
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
// Signing (PrivateKey.Sign) is added in Phase 2; this Phase 1 package
// only offers construction, encoding, and verification via the embedded
// PublicKey.
type PrivateKey struct {
	Params *Params
	SkSeed [32]byte
	PublicKey
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
// by Bytes.
func ParsePrivateKey(p *Params, b []byte) (*PrivateKey, error) {
	if len(b) != 64 {
		return nil, ErrInvalidPrivateKey
	}
	sk := &PrivateKey{Params: p}
	copy(sk.SkSeed[:], b[0:32])
	sk.PublicKey.Params = p
	copy(sk.PublicKey.Seed[:], b[32:48])
	copy(sk.PublicKey.Root[:], b[48:64])
	return sk, nil
}

// Zeroize overwrites the secret seed with zeros. Callers that hold a
// PrivateKey past its useful lifetime should call this where practical
// (SPEC §13); it is not a substitute for proper secret-handling
// discipline (e.g. avoiding secrets in swappable memory), which is
// outside what a pure-Go library can guarantee.
func (sk *PrivateKey) Zeroize() {
	for i := range sk.SkSeed {
		sk.SkSeed[i] = 0
	}
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

	root := subtreeRoot(p, pkSeedW, skSeedW, uint32(p.D-1), 0)

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
// to Sign.
func (sk *PrivateKey) Sign(msg []byte) ([]byte, error) {
	if len(msg) != 32 {
		return nil, ErrInvalidMessageLength
	}
	var msgArr [32]byte
	copy(msgArr[:], msg)

	var pkSeedW, pkRootW, skSeedW word
	copy(pkSeedW[:16], sk.PublicKey.Seed[:])
	copy(pkRootW[:16], sk.PublicKey.Root[:])
	copy(skSeedW[:], sk.SkSeed[:])

	return signInternal(sk.Params, pkSeedW, pkRootW, skSeedW, msgArr, nil)
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
	levels := buildSubtree(p, pkSeedW, skSeedW, layer, 0)

	return &Signer{
		sk:    sk,
		cache: &subtreeCache{layer: layer, tree: 0, levels: levels},
	}, nil
}

// Sign produces a deterministic SPHINCS⁻ signature over msg, exactly as
// sk.Sign(msg) would (byte-identical output), but reuses the cached
// top-layer subtree computed by NewSigner instead of rebuilding it.
func (s *Signer) Sign(msg []byte) ([]byte, error) {
	if len(msg) != 32 {
		return nil, ErrInvalidMessageLength
	}
	var msgArr [32]byte
	copy(msgArr[:], msg)

	sk := s.sk
	p := sk.Params

	var pkSeedW, pkRootW, skSeedW word
	copy(pkSeedW[:16], sk.PublicKey.Seed[:])
	copy(pkRootW[:16], sk.PublicKey.Root[:])
	copy(skSeedW[:], sk.SkSeed[:])

	return signInternal(p, pkSeedW, pkRootW, skSeedW, msgArr, s.cache)
}
