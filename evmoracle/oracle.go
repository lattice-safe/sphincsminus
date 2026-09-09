// Package evmoracle runs the real, upstream-compiled Solidity SPHINCS⁻
// verifiers inside go-ethereum's EVM interpreter, as the final
// compatibility oracle for github.com/lattice-safe/sphincsminus's Go
// signatures. It is a separate nested Go module purely so that the
// (heavy) go-ethereum dependency never touches the root module's
// go.sum (see docs/PLAN.md, Phase 3a).
//
// The verifier bytecode itself lives under evmoracle/testdata as
// *.bin-runtime files: the deployedBytecode.object of the upstream
// contracts at https://github.com/nconsigny/SPHINCS- (see the README
// in this directory for how they were produced). LoadVerifier loads
// one such file for a given *sphincsminus.Params, and Verifier.Verify
// executes it against a fresh in-memory EVM for a single call to
// verify(bytes32,bytes32,bytes32,bytes).
package evmoracle

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	stdruntime "runtime"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm/runtime"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"

	sphincsminus "github.com/lattice-safe/sphincsminus"
)

// selector is keccak256("verify(bytes32,bytes32,bytes32,bytes)")[:4],
// the Solidity ABI selector for the on-chain verify entry point (SPEC
// §12).
var selector = crypto.Keccak256([]byte("verify(bytes32,bytes32,bytes32,bytes)"))[:4]

// contractAddress is the fixed address the verifier bytecode is
// deployed to in the in-memory EVM used for each call.
var contractAddress = common.BytesToAddress([]byte("sphincsminus-evmoracle"))

// testdataDir returns the absolute path of evmoracle/testdata,
// resolved relative to this source file rather than the process's
// working directory, so LoadVerifier works regardless of the caller's
// cwd (not just when run via `go test` from the evmoracle package
// directory).
func testdataDir() string {
	_, file, _, ok := stdruntime.Caller(0)
	if !ok {
		return "testdata"
	}
	return filepath.Join(filepath.Dir(file), "testdata")
}

// Verifier wraps the compiled runtime bytecode of one upstream
// Solidity SPHINCS⁻ verifier contract, ready to execute against
// arbitrary (pkSeed, pkRoot, msg, sig) inputs.
type Verifier struct {
	// Params is the sphincsminus parameter set this verifier
	// corresponds to (its Name selects the testdata file).
	Params *sphincsminus.Params

	// Code is the EVM runtime (deployed) bytecode, decoded from hex.
	Code []byte
}

// verifierFile maps a Params.Name to its testdata/*.bin-runtime file
// basename.
func verifierFile(name string) string {
	return fmt.Sprintf("Sphincs%sAsm.bin-runtime", name)
}

// LoadVerifier loads the compiled Solidity verifier bytecode
// corresponding to p (by p.Name, e.g. "C13") from
// evmoracle/testdata/Sphincs<Name>Asm.bin-runtime.
func LoadVerifier(p *sphincsminus.Params) (*Verifier, error) {
	if p == nil {
		return nil, fmt.Errorf("evmoracle: nil params")
	}
	path := filepath.Join(testdataDir(), verifierFile(p.Name))
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("evmoracle: reading %s: %w", path, err)
	}
	hexStr := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(raw)), "0x"))
	code, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("evmoracle: decoding %s: %w", path, err)
	}
	return &Verifier{Params: p, Code: code}, nil
}

// leftPad32 left-pads b with zero bytes to a 32-byte word (the ABI
// encoding of a uint256/offset/length).
func leftPad32(v int64) []byte {
	return common.LeftPadBytes(big.NewInt(v).Bytes(), 32)
}

// EncodeCall ABI-encodes a call to the on-chain
// verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes sig)
// entry point (SPEC §12): selector ‖ pkSeed ‖ pkRoot ‖ msg ‖ offset(0x80)
// ‖ len(sig) ‖ sig ‖ zero-pad to a 32-byte boundary. It is exported so
// the future CLI (Phase 3b) can reuse it to print the same call data
// the upstream `forge` tests exercise.
func EncodeCall(pkSeed, pkRoot, msg [32]byte, sig []byte) []byte {
	out := make([]byte, 0, 4+32*4+((len(sig)+31)/32)*32)
	out = append(out, selector...)
	out = append(out, pkSeed[:]...)
	out = append(out, pkRoot[:]...)
	out = append(out, msg[:]...)
	out = append(out, leftPad32(0x80)...) // tail offset of the dynamic `bytes sig` argument
	out = append(out, leftPad32(int64(len(sig)))...)
	out = append(out, sig...)
	if pad := (32 - len(sig)%32) % 32; pad != 0 {
		out = append(out, make([]byte, pad)...)
	}
	return out
}

// newState builds a fresh in-memory state database with v.Code
// deployed at contractAddress, ready for a single call.
func (v *Verifier) newState() (*state.StateDB, error) {
	db, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	if err != nil {
		return nil, fmt.Errorf("evmoracle: new state: %w", err)
	}
	db.CreateAccount(contractAddress)
	db.SetCode(contractAddress, v.Code)
	return db, nil
}

// revertError wraps a non-nil error returned by runtime.Call/Execute
// when the EVM call reverted, decoding an Error(string) revert reason
// from ret when present (a bare `revert(0,0)` — SPEC §12 — carries no
// reason and is reported as-is).
type revertError struct {
	inner  error
	reason string
	data   []byte
}

func (e *revertError) Error() string {
	if e.reason != "" {
		return fmt.Sprintf("evmoracle: reverted: %s", e.reason)
	}
	if len(e.data) == 0 {
		return fmt.Sprintf("evmoracle: reverted (no reason): %v", e.inner)
	}
	return fmt.Sprintf("evmoracle: reverted (undecodable reason, data=0x%x): %v", e.data, e.inner)
}

func (e *revertError) Unwrap() error { return e.inner }

// Reason returns the decoded Error(string) revert reason, or "" if the
// revert carried no decodable reason (e.g. a bare `revert(0,0)`).
func (e *revertError) Reason() string { return e.reason }

// wrapRevert builds a *revertError from the EVM's returned data and
// error, decoding an Error(string) reason if present.
func wrapRevert(err error, ret []byte) error {
	reason, decodeErr := abi.UnpackRevert(ret)
	if decodeErr != nil {
		reason = ""
	}
	return &revertError{inner: err, reason: reason, data: ret}
}

// Verify runs v's verifier bytecode against (pkSeed, pkRoot, msg, sig)
// in a fresh in-memory EVM (params.AllDevChainProtocolChanges, i.e. the
// latest fork rules) and reports whether it returned `true`, the gas
// consumed, and any execution error. A Solidity `revert` (with or
// without a reason string, SPEC §12) is reported as a non-nil error
// (see revertError / Reason) rather than as valid=false; callers that
// want SPEC §12's "any failure ⇒ effectively invalid" semantics should
// treat (valid=false) OR (err != nil) as rejection.
func (v *Verifier) Verify(pkSeed, pkRoot, msg [32]byte, sig []byte) (valid bool, gasUsed uint64, err error) {
	input := EncodeCall(pkSeed, pkRoot, msg, sig)

	db, err := v.newState()
	if err != nil {
		return false, 0, err
	}

	const gasLimit = 30_000_000
	cfg := &runtime.Config{
		ChainConfig: params.AllDevChainProtocolChanges,
		GasLimit:    gasLimit,
		State:       db,
	}

	ret, leftOverGas, callErr := runtime.Call(contractAddress, input, cfg)
	gasUsed = gasLimit - leftOverGas

	if callErr != nil {
		return false, gasUsed, wrapRevert(callErr, ret)
	}
	if len(ret) != 32 {
		return false, gasUsed, fmt.Errorf("evmoracle: unexpected return data length %d (want 32)", len(ret))
	}
	// A Solidity `bool` return is ABI-encoded as a 32-byte word with the
	// value in the low byte (0 or 1).
	for _, b := range ret[:31] {
		if b != 0 {
			return false, gasUsed, fmt.Errorf("evmoracle: malformed bool return 0x%x", ret)
		}
	}
	return ret[31] != 0, gasUsed, nil
}
