# SPHINCS⁻ (SPHINCS minus) — Byte-level Specification for the Go Implementation

This document is the single source of truth for `github.com/lattice-safe/sphincsminus`.
It is transcribed from the reference implementation
(https://github.com/nconsigny/SPHINCS- : `src/keccak/SPHINCs-C13Asm.sol`,
`signer-wasm/src/*.rs`, `script/signer.py`) and MUST be followed byte-for-byte.
Any deviation makes signatures unverifiable by the on-chain Solidity verifiers.

Scope of v1: the **keccak C-series** variants (C7, C9, C10, C11, C13) that use the
**FIPS 205 §4.2 uncompressed 32-byte ADRS** and **keccak256**. Not in scope: C12
(plain SPHINCS+), SHA-256 / BLAKE2b twins, SLH-DSA-128-24, JARDIN legacy layout.

## 1. Notation

* `n = 16` bytes (128-bit) for every variant.
* All hash *node values* are handled internally as 32-byte big-endian words in
  **N_MASK form**: the top 16 bytes carry the value, the low 16 bytes are zero.
  `maskN(x) = x & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000`.
  On the wire (signature bytes) only the 16 significant bytes are stored.
* `be4(v)` = 4-byte big-endian; `be32(v)` = 32-byte big-endian (value in the low bytes).
* `‖` = concatenation. `keccak256` = Ethereum Keccak-256 (NOT SHA3-256, NOT SHAKE).
* The message is always exactly **32 bytes** (an EVM hash). No prehash mode, no context.

## 2. Parameter sets

| Name | h  | d | sh=h/d | a  | k  | w | log_w | l  | target_sum | sig bytes |
|------|----|---|--------|----|----|---|-------|----|------------|-----------|
| C7   | 24 | 2 | 12     | 16 | 8  | 8 | 3     | 43 | 151        | 3704      |
| C9   | 20 | 2 | 10     | 12 | 11 | 8 | 3     | 43 | 208        | 3816      |
| C10  | 18 | 2 | 9      | 11 | 13 | 8 | 3     | 43 | 205        | 4008      |
| C11  | 16 | 2 | 8      | 11 | 13 | 8 | 3     | 43 | 203        | 3976      |
| C13  | 22 | 2 | 11     | 19 | 7  | 8 | 3     | 43 | 208        | 3688      |

Derived quantities (must be computed, and asserted in tests):

```
FORS_START = n                          = 16
AUTH_START = n + k*n
HT_START   = AUTH_START + (k-1)*a*n
LAYER_SIZE = l*n + 4 + sh*n
SIG_SIZE   = HT_START + d*LAYER_SIZE
invariant: k*a + h <= 256
```

C13 is the recommended default (`3688` bytes, HT_START = 1952, LAYER_SIZE = 868).

## 3. Keys

* `pkSeed`: 16 significant bytes (stored masked as a 32-byte word).
* `skSeed`: **32 bytes** (full keccak output, NOT masked).
* `pkRoot`: 16 significant bytes = root of the top-layer subtree
  (`layer = d-1`, `tree = 0`), see §8.
* Public key wire encoding (Go API): `pkSeed[16] ‖ pkRoot[16]` = 32 bytes.
  On-chain the verifier takes `(bytes32 pkSeed, bytes32 pkRoot)` each top-aligned
  (low 16 bytes zero); the verifier rejects non-canonical (unmasked) keys.
* Private key wire encoding (Go API): `skSeed[32] ‖ pkSeed[16] ‖ pkRoot[16]` = 64 bytes.

### 3.1 Random key generation (Go default)
`skSeed = 32 random bytes; pkSeed = maskN(32 random bytes)` from `crypto/rand`,
then compute `pkRoot`.

### 3.2 Reference-compatible derivation (interop / test vectors only)
Matches `script/signer.py derive_keys` and `signer-c13 keygen`:
```
entropy = keccak256("sphincs_signer_v1" ‖ material32)
pkSeed  = maskN(keccak256("pk_seed" ‖ entropy))
skSeed  = keccak256("sk_seed" ‖ entropy)
```
KAT (from `signer-wasm/tests/cross_validate.rs`, entropy = 0x42*32 used *directly*,
i.e. `pkSeed = maskN(keccak256("pk_seed" ‖ 0x42*32))`):
```
pk_seed = 0x012dd57311a3728fd6988fb2a583bb9e00000000000000000000000000000000
sk_seed = 0x11d47d1635d4ad4852852dae8fd9dbbd699558d7907907cdae4203bdbae7f7aa
wotsSecret(sk_seed, layer=1, tree=0, kp=0, chain=0)
        = 0x60fd5cf59c3c018fca334b8538cc52fe00000000000000000000000000000000
forsSecret(sk_seed, htIdx=0, tree=0, leaf=0)
        = 0xf3c46060303099c9faed1691ad98823900000000000000000000000000000000
```

## 4. Address (ADRS) — FIPS 205 §4.2 uncompressed, 32 bytes big-endian

```
bytes  0.. 4  layer address   uint32
bytes  4..16  tree address    96-bit BE (we only ever use the low 64 bits; top 4 bytes 0)
bytes 16..20  type            uint32
bytes 20..24  word1
bytes 24..28  word2
bytes 28..32  word3
```

| type | name       | word1            | word2         | word3        |
|------|------------|------------------|---------------|--------------|
| 0    | WOTS_HASH  | key_pair_address | chain_address | hash_address |
| 1    | WOTS_PK    | key_pair_address | 0             | 0            |
| 2    | TREE       | 0                | tree_height   | tree_index   |
| 3    | FORS_TREE  | key_pair_address | tree_height   | tree_index   |
| 4    | FORS_ROOTS | key_pair_address | 0             | 0            |

As a uint256: `adrs = layer<<224 | tree<<128 | type<<96 | word1<<64 | word2<<32 | word3`.

## 5. Tweakable hashes (all inputs are 32-byte words; node values in N_MASK form)

```
Th(seed, adrs, x)            = maskN(keccak256(seed ‖ adrs ‖ x))                 (96 B in)
ThPair(seed, adrs, l, r)     = maskN(keccak256(seed ‖ adrs ‖ l ‖ r))             (128 B in)
ThMulti(seed, adrs, v[0..m]) = maskN(keccak256(seed ‖ adrs ‖ v[0] ‖ … ‖ v[m-1]))
HMsg(seed, root, R, msg)     = keccak256(seed ‖ root ‖ R ‖ msg ‖ 0xFF*32)        (160 B in, NOT masked, full 256 bits)
WotsDigest(seed, adrs0, m, c)= keccak256(seed ‖ adrs0 ‖ m ‖ be32(c))             (128 B in, NOT masked)
```
where for `WotsDigest`, `adrs0 = ADRS(layer, tree, type=0, word1=kp, word2=0, word3=0)`.

## 6. Signer-side PRFs (never seen by the verifier; must match reference for interop)

```
wotsSecret(skSeed, layer, tree, kp, chain) = maskN(keccak256(skSeed ‖ "wots" ‖ be4(layer) ‖ be32(tree) ‖ be4(kp) ‖ be4(chain)))
forsSecret(skSeed, htIdx, t, j)            = maskN(keccak256(skSeed ‖ "fors" ‖ be4(htIdx) ‖ be4(t) ‖ be4(j)))
R(skSeed, msg, nonce)                      = maskN(keccak256(skSeed ‖ "R_grind" ‖ msg ‖ be32(nonce)))
```
`skSeed` here is the full 32 bytes. String literals are ASCII bytes with no terminator.

## 7. Message digest and index parsing (LSB-first)

```
digest = HMsg(pkSeed, pkRoot, R, msg)                      // uint256
forsIdx[i] = (digest >> (i*a)) & (2^a - 1)     for i in 0..k-1
htIdx      = (digest >> (k*a)) & (2^h - 1)
idxLeaf0   = htIdx & (2^sh - 1)                            // bottom-layer leaf
idxTree0   = htIdx >> sh                                   // bottom-layer tree
```
**FORS+C forced-zero**: a valid signature requires `forsIdx[k-1] == 0`.
The signer grinds `nonce = 0,1,2,…` in `R(skSeed, msg, nonce)` until this holds
(expected 2^a attempts). Signing is therefore deterministic per (key, msg).

## 8. FORS+C

All FORS ADRS use `layer = 0`, `tree = idxTree0`, `word1 = idxLeaf0`
(the FORS instance is keyed by the per-message hypertree leaf).

```
leafAdrs(t, j)     = ADRS(0, idxTree0, 3, idxLeaf0, 0,    (t << a) | j)
nodeAdrs(t, hh, i) = ADRS(0, idxTree0, 3, idxLeaf0, hh,   (t << (a - hh)) | i)     hh in 1..a
rootsAdrs          = ADRS(0, idxTree0, 4, idxLeaf0, 0, 0)

leaf(t, j)   = Th(pkSeed, leafAdrs(t, j), forsSecret(skSeed, htIdx, t, j))
node(t,hh,i) = ThPair(pkSeed, nodeAdrs(t, hh, i), node(t,hh-1,2i), node(t,hh-1,2i+1))
root(t)      = node(t, a, 0)
```

Signing (trees `t = 0..k-2`): reveal `secret[t] = forsSecret(skSeed, htIdx, t, forsIdx[t])`
and the `a`-node authentication path (sibling at each height, bottom-up).
Tree `k-1` (forced-zero): reveal `secret[k-1] = root(k-1)` and **no auth path**.

FORS public key:
```
r[t]   = root(t)                                       t = 0..k-2 (recomputed by verifier from secret + path)
r[k-1] = Th(pkSeed, leafAdrs(k-1, 0), secret[k-1])     // root hashed as "leaf 0" of tree k-1
forsPk = ThMulti(pkSeed, rootsAdrs, r[0..k-1])
```
Verifier root recomputation (tree t, leaf index `idx = forsIdx[t]`):
```
node = Th(pkSeed, leafAdrs(t, idx), secret[t])
for hh in 0..a-1:
    sib    = auth[t][hh]
    parent = idx >> 1
    adrs   = nodeAdrs(t, hh+1, parent)
    node   = (idx & 1) == 0 ? ThPair(seed, adrs, node, sib) : ThPair(seed, adrs, sib, node)
    idx    = parent
```

## 9. WOTS+C (w = 8, l = 43 chains, digit sum grinding)

For a WOTS keypair at `(layer, tree, kp)`:
```
adrsHash(i, pos) = ADRS(layer, tree, 0, kp, i, pos)
adrsPk           = ADRS(layer, tree, 1, kp, 0, 0)

chain(x, start, steps): for pos in start .. start+steps-1: x = Th(pkSeed, adrsHash(i, pos), x); return x

sk[i] = wotsSecret(skSeed, layer, tree, kp, i)
pk[i] = chain(sk[i], 0, w-1)                     // 7 steps
wotsPk = ThMulti(pkSeed, adrsPk, pk[0..l-1])
```
Signing message `m` (a 32-byte N_MASK node value):
```
find smallest count >= 0 such that:
    D = WotsDigest(pkSeed, ADRS(layer,tree,0,kp,0,0), m, count)
    digit[i] = (D >> (3*i)) & 7        for i in 0..l-1        (LSB-first, digits straddle bytes)
    sum(digit) == target_sum
sig[i] = chain(sk[i], 0, digit[i])
emit: sig[0..l-1] (16 B each) ‖ be4(count)
```
Verification: recompute `D` from `count`, reject if `sum(digit) != target_sum`,
`pk[i] = chain(sig[i], digit[i], w-1-digit[i])`, `wotsPk = ThMulti(...)`.
There is **no checksum** (the target-sum replaces it).

## 10. Hypertree (d layers of XMSS subtrees of height sh)

```
treeAdrs(layer, tree, hh, i) = ADRS(layer, tree, 2, 0, hh, i)      hh in 1..sh
leaf(layer, tree, kp)        = wotsPk(layer, tree, kp)
node(hh, i)                  = ThPair(pkSeed, treeAdrs(layer, tree, hh, i), node(hh-1, 2i), node(hh-1, 2i+1))
```
Signing:
```
cur = forsPk ; idxTree = htIdx
for layer in 0..d-1:
    idxLeaf = idxTree & (2^sh - 1) ; idxTree >>= sh
    (wotsSig, count) = WOTS+C sign of cur with keypair (layer, idxTree, idxLeaf)
    auth = auth path of leaf idxLeaf in subtree (layer, idxTree)
    cur  = root of that subtree (verifier recomputes it from wotsPk + auth, same swap rule as §8)
require cur == pkRoot
```
`pkRoot = root of subtree (layer = d-1, tree = 0)`. (`idxTree` after the last
shift is always 0 because `k*a + h` bits are consumed and `h = d*sh`.)

## 11. Signature wire layout (big-endian, each node 16 bytes)

```
[0, 16)                              R
[16, 16 + k*16)                      FORS secrets, t = 0..k-1  (secret[k-1] is root(k-1))
[AUTH_START, HT_START)               FORS auth paths, t = 0..k-2, each a*16 bytes, height 0 first
HT_START + layer*LAYER_SIZE:
    [0, l*16)                        WOTS sig chains 0..l-1
    [l*16, l*16 + 4)                 count, uint32 big-endian
    [l*16 + 4, l*16 + 4 + sh*16)     XMSS auth path, height 0 first
```
Verify MUST reject (return false, no panic) when: `len(sig) != SIG_SIZE`,
`len(msg) != 32`, `len(pk) != 32`, forced-zero violated, any layer's digit sum
!= target_sum, or final root != pkRoot. Compare roots in constant time.

## 12. Reference tool output formats (for cross-testing)

`signer.py <variant> <msg>` and `signer-c13 sign <msg>` print
`abi.encode(bytes32 pkSeed, bytes32 pkRoot, bytes sig)` as hex:
`pkSeed32 ‖ pkRoot32 ‖ 0x60 ‖ len ‖ sig ‖ zero-pad to 32`. In that mode keys are
derived from the *message* via §3.2 with `material = msg`.
`signer-c13 keygen <material>` prints JSON `{"seed","sk_seed","root"}`;
`signer-c13 sign-with <seed> <sk_seed> <root> <msg>` prints the raw sig hex.

Solidity verifier ABI: `verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes sig) returns (bool)`,
selector = `keccak256("verify(bytes32,bytes32,bytes32,bytes)")[:4]`.
On-chain failure semantics (verified by executing the compiled bytecode in go-ethereum):
* wrong `sig.length` → `revert("Invalid sig length")` (all five);
* non-canonical `pkSeed`/`pkRoot` (low 128 bits non-zero) → `revert("Invalid public key")` (all five);
* forced-zero violation or WOTS digit-sum mismatch → **C13 returns `false`**, **C7/C9/C10/C11 `revert(0,0)`**;
* final root mismatch → returns `false` (all five).
Note a corrupted FORS byte usually surfaces as a digit-sum mismatch at layer 0 (the WOTS
message changes), so on C7/C9/C10/C11 most corruptions revert rather than return false.
The Go `Verify` returns `false` in every failure case.

## 13. Security notes to carry into docs

* Research-grade construction, not FIPS 205, not audited. Signature budget per
  key is 2^h (C13: 2^22) with 128-bit security across the window per the paper.
* Signing is deterministic; the same (key, msg) always yields the same signature.
* `skSeed` must be zeroized after use where practical.
