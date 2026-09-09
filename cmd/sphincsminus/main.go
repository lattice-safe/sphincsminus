// Command sphincsminus is a stdlib-only CLI around the sphincsminus
// package: key generation, signing, verification, parameter-set listing,
// and a reference-compatible "vector" mode that prints the same
// ABI-encoded (pkSeed, pkRoot, sig) hex the upstream Rust/Python signers
// print, so Foundry FFI tests can shell out to this binary instead of
// Python (SPEC.md §12).
//
// See docs/SPEC.md and docs/PLAN.md (Phase 3b) in the repository root for
// the byte-level contract this CLI wraps.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/lattice-safe/sphincsminus"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// Exit codes shared by every subcommand.
const (
	exitOK      = 0
	exitInvalid = 1 // verify: signature does not verify
	exitUsage   = 2 // bad flags, bad hex, wrong length, I/O error, etc.
)

const topUsage = `sphincsminus is a CLI for the github.com/lattice-safe/sphincsminus SPHINCS- library.

Usage:

	sphincsminus <command> [arguments]

Commands:

	keygen    generate (or reference-derive) a key pair
	sign      sign a 32-byte message with a private key
	verify    verify a signature against a public key and message
	vector    print the upstream ABI-encoded (pkSeed, pkRoot, sig) hex
	params    print the table of supported parameter sets

Use "sphincsminus <command> -h" for details on a command.
`

// run executes the CLI and returns a process exit code. It never calls
// os.Exit itself, so tests can drive it in-process.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, topUsage)
		return exitUsage
	}

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "keygen":
		return cmdKeygen(rest, stdout, stderr)
	case "sign":
		return cmdSign(rest, stdout, stderr)
	case "verify":
		return cmdVerify(rest, stdout, stderr)
	case "vector":
		return cmdVector(rest, stdout, stderr)
	case "params":
		return cmdParams(rest, stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, topUsage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "sphincsminus: unknown command %q\n\n", cmd)
		fmt.Fprint(stderr, topUsage)
		return exitUsage
	}
}

// ---------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------

// keygenOutput is the JSON shape printed by "keygen" and consumed by
// "sign -key".
type keygenOutput struct {
	Params     string `json:"params"`
	PkSeed     string `json:"pkSeed"`
	PkRoot     string `json:"pkRoot"`
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

// hex0x hex-encodes b with a leading "0x".
func hex0x(b []byte) string {
	return "0x" + hex.EncodeToString(b)
}

// parseHexBytes decodes a hex string that may or may not have a leading
// "0x"/"0X" prefix.
func parseHexBytes(s string) ([]byte, error) {
	t := strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if t == "" {
		return nil, fmt.Errorf("empty hex string")
	}
	b, err := hex.DecodeString(t)
	if err != nil {
		return nil, fmt.Errorf("invalid hex %q: %w", s, err)
	}
	return b, nil
}

// parseHexN decodes a hex string and requires it to be exactly n bytes.
// name is used in error messages (e.g. "-msg").
func parseHexN(s string, n int, name string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("%s: missing required value", name)
	}
	b, err := parseHexBytes(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if len(b) != n {
		return nil, fmt.Errorf("%s: expected %d bytes, got %d", name, n, len(b))
	}
	return b, nil
}

// lookupParams resolves a parameter-set name case-insensitively against
// sphincsminus.AllParams.
func lookupParams(name string) (*sphincsminus.Params, error) {
	for _, p := range sphincsminus.AllParams {
		if strings.EqualFold(p.Name, name) {
			return p, nil
		}
	}
	names := make([]string, len(sphincsminus.AllParams))
	for i, p := range sphincsminus.AllParams {
		names[i] = p.Name
	}
	return nil, fmt.Errorf("unknown params %q (want one of %s)", name, strings.Join(names, ", "))
}

// abiEncode reproduces the upstream reference tools' output format
// (SPEC §12): abi.encode(bytes32 pkSeed, bytes32 pkRoot, bytes sig) =
// pkSeed ‖ pkRoot ‖ 0x60 (32 B offset) ‖ len(sig) (32 B) ‖ sig ‖
// zero-pad to a 32-byte boundary.
func abiEncode(pkSeed, pkRoot [32]byte, sig []byte) []byte {
	out := make([]byte, 0, 96+((len(sig)+31)/32)*32)
	out = append(out, pkSeed[:]...)
	out = append(out, pkRoot[:]...)

	var word [32]byte
	word[31] = 0x60
	out = append(out, word[:]...)

	word = [32]byte{}
	binary.BigEndian.PutUint64(word[24:32], uint64(len(sig)))
	out = append(out, word[:]...)

	out = append(out, sig...)
	if pad := (32 - len(sig)%32) % 32; pad != 0 {
		out = append(out, make([]byte, pad)...)
	}
	return out
}

// errUsage prints err to stderr (prefixed with the subcommand's usage on
// request) and returns the usage exit code. It's a small helper to keep
// every subcommand's error path identical.
func errUsage(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "error: %v\n", err)
	return exitUsage
}

// explicitFlags reports which flags were actually set on the command
// line (as opposed to left at their default), keyed by flag name.
func explicitFlags(fs *flag.FlagSet) map[string]bool {
	seen := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	return seen
}

// ---------------------------------------------------------------------
// keygen
// ---------------------------------------------------------------------

const keygenUsage = `usage: sphincsminus keygen [-params C13] [-material 0xHEX32] [-out file]

Generate a SPHINCS- key pair and print it as JSON:

	{"params","pkSeed","pkRoot","publicKey","privateKey"}

pkSeed/pkRoot are the 32-byte top-aligned (N_MASK) on-chain word form;
publicKey is the 32-byte wire form (pkSeed16‖pkRoot16); privateKey is the
64-byte wire form (skSeed32‖pkSeed16‖pkRoot16).

Without -material, a fresh key is sampled from crypto/rand (GenerateKey).
With -material, the key is derived deterministically from the given
32-byte material the same way the reference Rust/Python signers do
(DeriveKeyReference, SPEC §3.2): this is for cross-testing against
reference vectors, NOT for production keys, since the key is fully
determined by (and only as secret as) the material.

Flags:
`

func cmdKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, keygenUsage)
		fs.PrintDefaults()
	}
	paramsName := fs.String("params", "C13", "parameter set (case-insensitive): C7, C9, C10, C11, C13")
	material := fs.String("material", "", "32-byte hex material for reference-compatible deterministic derivation")
	outFile := fs.String("out", "", "write JSON to this file (mode 0600) instead of stdout")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}

	p, err := lookupParams(*paramsName)
	if err != nil {
		return errUsage(stderr, err)
	}

	var sk *sphincsminus.PrivateKey
	if *material != "" {
		matBytes, err := parseHexN(*material, 32, "-material")
		if err != nil {
			return errUsage(stderr, err)
		}
		var m [32]byte
		copy(m[:], matBytes)
		fmt.Fprintln(stderr, "warning: -material derives a fully deterministic key from that material "+
			"(reference-compatible derivation, SPEC §3.2); use this only for test vectors/interop, "+
			"never for a key that needs to stay secret")
		sk, err = sphincsminus.DeriveKeyReference(p, m)
		if err != nil {
			return errUsage(stderr, err)
		}
	} else {
		sk, err = sphincsminus.GenerateKey(p)
		if err != nil {
			return errUsage(stderr, err)
		}
	}

	seedWord := sk.PublicKey.SeedWord()
	rootWord := sk.PublicKey.RootWord()
	out := keygenOutput{
		Params:     p.Name,
		PkSeed:     hex0x(seedWord[:]),
		PkRoot:     hex0x(rootWord[:]),
		PublicKey:  hex0x(sk.PublicKey.Bytes()),
		PrivateKey: hex0x(sk.Bytes()),
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return errUsage(stderr, fmt.Errorf("encode JSON: %w", err))
	}
	data = append(data, '\n')

	if *outFile != "" {
		if err := os.WriteFile(*outFile, data, 0600); err != nil {
			return errUsage(stderr, fmt.Errorf("write %s: %w", *outFile, err))
		}
		return exitOK
	}
	if _, err := stdout.Write(data); err != nil {
		return errUsage(stderr, err)
	}
	return exitOK
}

// ---------------------------------------------------------------------
// sign
// ---------------------------------------------------------------------

const signUsage = `usage: sphincsminus sign -params C13 (-sk 0xHEX64 | -key file.json) -msg 0xHEX32 [-o file]

Sign a 32-byte message with a private key, printing the signature as
0x-prefixed hex (or writing raw signature bytes to -o).

-sk takes the 64-byte private-key wire form (skSeed32‖pkSeed16‖pkRoot16),
as printed by "keygen"'s "privateKey" field. -key is an alternative that
reads a keygen JSON file directly; if -params is not also given
explicitly, the key file's "params" field is used.

Flags:
`

func cmdSign(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, signUsage)
		fs.PrintDefaults()
	}
	paramsName := fs.String("params", "C13", "parameter set (case-insensitive): C7, C9, C10, C11, C13")
	skHex := fs.String("sk", "", "64-byte private key hex (skSeed32‖pkSeed16‖pkRoot16)")
	keyFile := fs.String("key", "", "keygen JSON file to read the private key from")
	msgHex := fs.String("msg", "", "32-byte message hex")
	outFile := fs.String("o", "", "write raw signature bytes to this file instead of printing hex")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	seen := explicitFlags(fs)

	if *skHex == "" && *keyFile == "" {
		return errUsage(stderr, fmt.Errorf("one of -sk or -key is required"))
	}
	if *skHex != "" && *keyFile != "" {
		return errUsage(stderr, fmt.Errorf("-sk and -key are mutually exclusive"))
	}

	var skHexValue string
	if *keyFile != "" {
		data, err := os.ReadFile(*keyFile)
		if err != nil {
			return errUsage(stderr, fmt.Errorf("read %s: %w", *keyFile, err))
		}
		var kf keygenOutput
		if err := json.Unmarshal(data, &kf); err != nil {
			return errUsage(stderr, fmt.Errorf("parse %s: %w", *keyFile, err))
		}
		if kf.PrivateKey == "" {
			return errUsage(stderr, fmt.Errorf("%s: missing \"privateKey\" field", *keyFile))
		}
		if !seen["params"] {
			*paramsName = kf.Params
		} else if kf.Params != "" && !strings.EqualFold(kf.Params, *paramsName) {
			return errUsage(stderr, fmt.Errorf("-params %s does not match %s's params %s", *paramsName, *keyFile, kf.Params))
		}
		skHexValue = kf.PrivateKey
	} else {
		skHexValue = *skHex
	}

	p, err := lookupParams(*paramsName)
	if err != nil {
		return errUsage(stderr, err)
	}
	skBytes, err := parseHexN(skHexValue, 64, "private key")
	if err != nil {
		return errUsage(stderr, err)
	}
	msgBytes, err := parseHexN(*msgHex, 32, "-msg")
	if err != nil {
		return errUsage(stderr, err)
	}

	sk, err := sphincsminus.ParsePrivateKey(p, skBytes)
	if err != nil {
		return errUsage(stderr, err)
	}

	sig, err := sk.Sign(msgBytes)
	if err != nil {
		return errUsage(stderr, err)
	}

	if *outFile != "" {
		if err := os.WriteFile(*outFile, sig, 0600); err != nil {
			return errUsage(stderr, fmt.Errorf("write %s: %w", *outFile, err))
		}
		return exitOK
	}
	fmt.Fprintln(stdout, hex0x(sig))
	return exitOK
}

// ---------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------

const verifyUsage = `usage: sphincsminus verify -params C13 -pk 0xHEX32 -msg 0xHEX32 -sig (0xHEX|@file)

Verify a signature against a public key and message, printing "valid" or
"invalid". -sig accepts either hex, or "@path" to read raw signature
bytes from a file.

Exit codes: 0 valid, 1 invalid, 2 usage/parse error.

Flags:
`

func cmdVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, verifyUsage)
		fs.PrintDefaults()
	}
	paramsName := fs.String("params", "C13", "parameter set (case-insensitive): C7, C9, C10, C11, C13")
	pkHex := fs.String("pk", "", "32-byte public key hex (pkSeed16‖pkRoot16)")
	msgHex := fs.String("msg", "", "32-byte message hex")
	sigArg := fs.String("sig", "", "signature hex, or @path to read raw signature bytes from a file")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}

	p, err := lookupParams(*paramsName)
	if err != nil {
		return errUsage(stderr, err)
	}
	pkBytes, err := parseHexN(*pkHex, 32, "-pk")
	if err != nil {
		return errUsage(stderr, err)
	}
	msgBytes, err := parseHexN(*msgHex, 32, "-msg")
	if err != nil {
		return errUsage(stderr, err)
	}
	if *sigArg == "" {
		return errUsage(stderr, fmt.Errorf("-sig: missing required value"))
	}

	var sigBytes []byte
	if path, ok := strings.CutPrefix(*sigArg, "@"); ok {
		sigBytes, err = os.ReadFile(path)
		if err != nil {
			return errUsage(stderr, fmt.Errorf("read %s: %w", path, err))
		}
	} else {
		sigBytes, err = parseHexBytes(*sigArg)
		if err != nil {
			return errUsage(stderr, fmt.Errorf("-sig: %w", err))
		}
	}

	pk, err := sphincsminus.ParsePublicKey(p, pkBytes)
	if err != nil {
		return errUsage(stderr, err)
	}

	// pk.Verify (and the Verify it wraps) never panics and rejects
	// malformed/mismatched-length signatures by returning false, so any
	// content-level problem with -sig (wrong length, wrong bytes, wrong
	// message) surfaces as an ordinary "invalid" result (exit 1), not a
	// usage error.
	if pk.Verify(msgBytes, sigBytes) {
		fmt.Fprintln(stdout, "valid")
		return exitOK
	}
	fmt.Fprintln(stdout, "invalid")
	return exitInvalid
}

// ---------------------------------------------------------------------
// vector
// ---------------------------------------------------------------------

const vectorUsage = `usage: sphincsminus vector -params C13 -msg 0xHEX32 [-material 0xHEX32]

Derive a key (reference-compatible derivation, SPEC §3.2) from -material
(default: the message itself, exactly like the upstream
"signer.py <variant> <msg>" / "signer-c13 sign <msg>"), sign -msg with
it, and print the upstream ABI encoding as hex:

	pkSeed32 ‖ pkRoot32 ‖ 0x60 (32 B offset) ‖ len(sig) (32 B) ‖ sig ‖ zero-pad to 32

This is byte-identical to the upstream Rust/Python reference tools, so
Foundry FFI tests can call this binary instead of Python.

Flags:
`

func cmdVector(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("vector", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, vectorUsage)
		fs.PrintDefaults()
	}
	paramsName := fs.String("params", "C13", "parameter set (case-insensitive): C7, C9, C10, C11, C13")
	msgHex := fs.String("msg", "", "32-byte message hex")
	materialHex := fs.String("material", "", "32-byte hex derivation material (default: the message itself)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}

	p, err := lookupParams(*paramsName)
	if err != nil {
		return errUsage(stderr, err)
	}
	msgBytes, err := parseHexN(*msgHex, 32, "-msg")
	if err != nil {
		return errUsage(stderr, err)
	}

	var material [32]byte
	if *materialHex != "" {
		m, err := parseHexN(*materialHex, 32, "-material")
		if err != nil {
			return errUsage(stderr, err)
		}
		copy(material[:], m)
	} else {
		copy(material[:], msgBytes)
	}

	sk, err := sphincsminus.DeriveKeyReference(p, material)
	if err != nil {
		return errUsage(stderr, err)
	}
	sig, err := sk.Sign(msgBytes)
	if err != nil {
		return errUsage(stderr, err)
	}

	abi := abiEncode(sk.PublicKey.SeedWord(), sk.PublicKey.RootWord(), sig)
	fmt.Fprintln(stdout, hex0x(abi))
	return exitOK
}

// ---------------------------------------------------------------------
// params
// ---------------------------------------------------------------------

const paramsUsage = `usage: sphincsminus params

Print a table of every supported parameter set (name, h, d, a, k, w, l,
target_sum, sig bytes).
`

func cmdParams(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("params", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, paramsUsage) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}

	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tH\tD\tA\tK\tW\tL\tTARGET_SUM\tSIG_BYTES")
	for _, p := range sphincsminus.AllParams {
		fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",
			p.Name, p.H, p.D, p.A, p.K, p.W, p.L, p.TargetSum, p.SigBytes())
	}
	if err := w.Flush(); err != nil {
		return errUsage(stderr, err)
	}
	if _, err := stdout.Write(buf.Bytes()); err != nil {
		return errUsage(stderr, err)
	}
	return exitOK
}
