package sphincsminus

import "encoding/binary"

// ADRS type constants (SPEC §4). As a uint256 the address is
// layer<<224 | tree<<128 | type<<96 | word1<<64 | word2<<32 | word3.
const (
	adrsWotsHash  uint32 = 0 // word1=key_pair_address, word2=chain_address,  word3=hash_address
	adrsWotsPk    uint32 = 1 // word1=key_pair_address, word2=0,              word3=0
	adrsTree      uint32 = 2 // word1=0,                word2=tree_height,   word3=tree_index
	adrsForsTree  uint32 = 3 // word1=key_pair_address, word2=tree_height,   word3=tree_index
	adrsForsRoots uint32 = 4 // word1=key_pair_address, word2=0,              word3=0
)

// newAdrs builds a FIPS 205 §4.2 uncompressed 32-byte ADRS (SPEC §4):
//
//	bytes  0.. 4  layer address   uint32
//	bytes  4..16  tree address    96-bit BE (low 64 bits used; top 4 bytes 0)
//	bytes 16..20  type            uint32
//	bytes 20..24  word1
//	bytes 24..28  word2
//	bytes 28..32  word3
//
// tree is truncated to its low 64 bits, which is all this spec's variants
// ever need (bytes 4..8 are always zero).
func newAdrs(layer uint32, tree uint64, typ uint32, w1, w2, w3 uint32) word {
	var a word
	binary.BigEndian.PutUint32(a[0:4], layer)
	binary.BigEndian.PutUint64(a[8:16], tree)
	binary.BigEndian.PutUint32(a[16:20], typ)
	binary.BigEndian.PutUint32(a[20:24], w1)
	binary.BigEndian.PutUint32(a[24:28], w2)
	binary.BigEndian.PutUint32(a[28:32], w3)
	return a
}

// setType overwrites the type field (bytes 16..20) of an ADRS in place.
func setType(a *word, typ uint32) {
	binary.BigEndian.PutUint32(a[16:20], typ)
}

// setWord2 overwrites word2 (bytes 24..28) of an ADRS in place.
func setWord2(a *word, w2 uint32) {
	binary.BigEndian.PutUint32(a[24:28], w2)
}

// setWord3 overwrites word3 (bytes 28..32) of an ADRS in place.
func setWord3(a *word, w3 uint32) {
	binary.BigEndian.PutUint32(a[28:32], w3)
}
