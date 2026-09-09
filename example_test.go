package sphincsminus

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// Example_signAndVerify demonstrates the core Go API: generate a key,
// sign a 32-byte message, and verify the resulting signature. C11 is
// used here (rather than the recommended default, C13) purely so the
// example runs quickly; production callers who want the largest possible
// per-key signature budget should prefer C13 (see the README's parameter
// table and docs/SPEC.md §2/§13).
func Example_signAndVerify() {
	sk, err := GenerateKey(C11)
	if err != nil {
		panic(err)
	}

	// The message is always exactly 32 bytes -- an EVM hash (SPEC §1).
	// Sign never sees or produces anything longer or shorter than that.
	var msg [32]byte
	copy(msg[:], []byte("sphincsminus example message"))

	sig, err := sk.Sign(msg[:])
	if err != nil {
		panic(err)
	}

	fmt.Println("signature has the expected length:", len(sig) == C11.SigBytes())
	fmt.Println("verifies under the signer's own public key:", sk.PublicKey.Verify(msg[:], sig))

	wrongMsg := msg
	wrongMsg[0] ^= 0x01
	fmt.Println("rejects a different message:", !sk.PublicKey.Verify(wrongMsg[:], sig))

	// Output:
	// signature has the expected length: true
	// verifies under the signer's own public key: true
	// rejects a different message: true
}

// Example_solidityABI demonstrates the two fields of a PublicKey that map
// directly onto the on-chain Solidity verifier's bytes32 arguments (SPEC
// §3), and how a client assembles the calldata for the ABI signature
//
//	verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes sig) returns (bool)
//
// (SPEC §12). This only builds the calldata bytes -- it does not execute
// any EVM code. Actually running the compiled Solidity bytecode against
// output like this lives in the separate evmoracle/ nested module, which
// drives go-ethereum's EVM directly (see docs/PLAN.md).
func Example_solidityABI() {
	sk, err := GenerateKey(C11)
	if err != nil {
		panic(err)
	}

	var msg [32]byte
	copy(msg[:], []byte("solidity abi example message"))

	sig, err := sk.Sign(msg[:])
	if err != nil {
		panic(err)
	}

	// SeedWord/RootWord return the 16-byte Seed/Root top-aligned in a
	// 32-byte N_MASK word: exactly the bytes32 encoding the on-chain
	// verifier expects (low 16 bytes zero; a non-canonical, i.e.
	// non-zero-low-bytes, key is rejected on-chain, SPEC §12).
	pkSeed := sk.PublicKey.SeedWord()
	pkRoot := sk.PublicKey.RootWord()

	// selector = keccak256("verify(bytes32,bytes32,bytes32,bytes)")[:4]
	var sel word
	hashBytes(&sel, []byte("verify(bytes32,bytes32,bytes32,bytes)"))
	selector := sel[:4]

	// Standard Solidity ABI encoding for (bytes32, bytes32, bytes32,
	// bytes): the first three 32-byte head words are the bytes32 values
	// verbatim; the fourth head word is the byte offset (measured from
	// the start of the argument block, i.e. right after the selector) to
	// the dynamic `bytes` tail, which is itself length-prefixed and
	// right-padded to a 32-byte boundary. This is exactly what SPEC §12
	// says the reference `signer.py`/`signer-c13` tools print for
	// cross-testing, minus the leading selector (they emit only the
	// argument encoding, since it's meant to be fed to `abi.decode` in a
	// test, not sent as a transaction).
	const headWords = 4
	tailOffset := uint64(headWords * 32)

	var offsetWord, lenWord [32]byte
	binary.BigEndian.PutUint64(offsetWord[24:], tailOffset)
	binary.BigEndian.PutUint64(lenWord[24:], uint64(len(sig)))

	calldata := append([]byte{}, selector...)
	calldata = append(calldata, pkSeed[:]...)
	calldata = append(calldata, pkRoot[:]...)
	calldata = append(calldata, msg[:]...)
	calldata = append(calldata, offsetWord[:]...)
	calldata = append(calldata, lenWord[:]...)
	calldata = append(calldata, sig...)
	if pad := (32 - len(sig)%32) % 32; pad != 0 {
		calldata = append(calldata, make([]byte, pad)...)
	}

	fmt.Println("selector:", hex.EncodeToString(selector))
	fmt.Println("pkSeed is top-aligned (low 16 bytes zero):", pkSeed[16] == 0 && pkSeed[31] == 0)
	fmt.Println("pkRoot is top-aligned (low 16 bytes zero):", pkRoot[16] == 0 && pkRoot[31] == 0)
	fmt.Println("calldata is whole 32-byte words after the selector:", (len(calldata)-len(selector))%32 == 0)

	// Output:
	// selector: 2bf6eda8
	// pkSeed is top-aligned (low 16 bytes zero): true
	// pkRoot is top-aligned (low 16 bytes zero): true
	// calldata is whole 32-byte words after the selector: true
}
