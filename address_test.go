package sphincsminus

import (
	"encoding/binary"
	"testing"
)

// handAdrs builds the expected ADRS bytes directly from the field layout
// in SPEC §4, independently of newAdrs, so these tests catch a bug in
// newAdrs's byte offsets rather than merely re-testing its own logic.
func handAdrs(layer uint32, tree uint64, typ, w1, w2, w3 uint32) [32]byte {
	var b [32]byte
	binary.BigEndian.PutUint32(b[0:4], layer)
	// bytes 4..16: 96-bit tree address, top 4 bytes zero, low 8 bytes = tree.
	binary.BigEndian.PutUint64(b[8:16], tree)
	binary.BigEndian.PutUint32(b[16:20], typ)
	binary.BigEndian.PutUint32(b[20:24], w1)
	binary.BigEndian.PutUint32(b[24:28], w2)
	binary.BigEndian.PutUint32(b[28:32], w3)
	return b
}

func TestNewAdrsWotsHash(t *testing.T) {
	// layer=1, tree=2, type=WOTS_HASH(0), kp=3, chain=4, hash=5.
	got := newAdrs(1, 2, adrsWotsHash, 3, 4, 5)
	want := handAdrs(1, 2, 0, 3, 4, 5)
	if word(want) != got {
		t.Errorf("newAdrs(1,2,WOTS_HASH,3,4,5) = %x, want %x", got, want)
	}
	// Spelled out byte-for-byte per SPEC §4:
	// [00000001][000000000000000000000002][00000000][00000003][00000004][00000005]
	wantBytes := [32]byte{
		0x00, 0x00, 0x00, 0x01, // layer = 1
		0x00, 0x00, 0x00, 0x00, // top 4 bytes of tree field, always 0
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // tree = 2 (low 8 bytes)
		0x00, 0x00, 0x00, 0x00, // type = WOTS_HASH = 0
		0x00, 0x00, 0x00, 0x03, // word1 = kp = 3
		0x00, 0x00, 0x00, 0x04, // word2 = chain = 4
		0x00, 0x00, 0x00, 0x05, // word3 = hash = 5
	}
	if [32]byte(got) != wantBytes {
		t.Errorf("newAdrs(1,2,WOTS_HASH,3,4,5) = %x, want %x", got, wantBytes)
	}
}

func TestNewAdrsTree(t *testing.T) {
	// TREE type: layer=0, tree=100, word1=0 (always, per the type=2 row of
	// the SPEC §4 table), word2=tree_height=7, word3=tree_index=9.
	got := newAdrs(0, 100, adrsTree, 0, 7, 9)
	wantBytes := [32]byte{
		0x00, 0x00, 0x00, 0x00, // layer = 0
		0x00, 0x00, 0x00, 0x00, // top 4 bytes of tree field
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, // tree = 100
		0x00, 0x00, 0x00, 0x02, // type = TREE = 2
		0x00, 0x00, 0x00, 0x00, // word1 = 0
		0x00, 0x00, 0x00, 0x07, // word2 = tree_height = 7
		0x00, 0x00, 0x00, 0x09, // word3 = tree_index = 9
	}
	if [32]byte(got) != wantBytes {
		t.Errorf("newAdrs(0,100,TREE,0,7,9) = %x, want %x", got, wantBytes)
	}
}

func TestNewAdrsForsRoots(t *testing.T) {
	// FORS_ROOTS type: layer=0, tree=0, word1=key_pair_address(idxLeaf0)=42,
	// word2=0, word3=0.
	got := newAdrs(0, 0, adrsForsRoots, 42, 0, 0)
	wantBytes := [32]byte{
		0x00, 0x00, 0x00, 0x00, // layer = 0
		0x00, 0x00, 0x00, 0x00, // top 4 bytes of tree field
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // tree = 0
		0x00, 0x00, 0x00, 0x04, // type = FORS_ROOTS = 4
		0x00, 0x00, 0x00, 0x2a, // word1 = 42 = 0x2a
		0x00, 0x00, 0x00, 0x00, // word2 = 0
		0x00, 0x00, 0x00, 0x00, // word3 = 0
	}
	if [32]byte(got) != wantBytes {
		t.Errorf("newAdrs(0,0,FORS_ROOTS,42,0,0) = %x, want %x", got, wantBytes)
	}
}

func TestAdrsSetters(t *testing.T) {
	a := newAdrs(0, 0, adrsWotsHash, 1, 2, 3)

	setWord2(&a, 99)
	if got := binary.BigEndian.Uint32(a[24:28]); got != 99 {
		t.Errorf("setWord2: word2 = %d, want 99", got)
	}

	setWord3(&a, 100)
	if got := binary.BigEndian.Uint32(a[28:32]); got != 100 {
		t.Errorf("setWord3: word3 = %d, want 100", got)
	}

	setType(&a, adrsTree)
	if got := binary.BigEndian.Uint32(a[16:20]); got != adrsTree {
		t.Errorf("setType: type = %d, want %d", got, adrsTree)
	}
	// setType/setWord2/setWord3 must not disturb layer/tree/word1.
	if binary.BigEndian.Uint32(a[0:4]) != 0 {
		t.Errorf("setType disturbed layer")
	}
	if binary.BigEndian.Uint32(a[20:24]) != 1 {
		t.Errorf("setType/setWord2/setWord3 disturbed word1")
	}
}
