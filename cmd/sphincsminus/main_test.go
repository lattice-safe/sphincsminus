package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------
// testdata/vectors/*.json loading (mirrors the root package's
// vectors_test.go, but this package can't import unexported test
// helpers from a different package, so it keeps its own minimal copy).
// ---------------------------------------------------------------------

type vectorFile struct {
	Variant string        `json:"variant"`
	Vectors []vectorEntry `json:"vectors"`
}

type vectorEntry struct {
	Name      string `json:"name"`
	Message   string `json:"message"`
	PkSeed    string `json:"pkSeed"`
	PkRoot    string `json:"pkRoot"`
	Signature string `json:"signature"`
}

// repoRoot is testdata/vectors' location relative to this package
// (cmd/sphincsminus is two directories below the module root).
const repoRoot = "../.."

func loadVectorEntry(t *testing.T, variantFile, name string) vectorEntry {
	t.Helper()
	path := filepath.Join(repoRoot, "testdata", "vectors", variantFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	for _, e := range vf.Vectors {
		if e.Name == name {
			return e
		}
	}
	t.Fatalf("%s: no vector named %q", path, name)
	return vectorEntry{}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := parseHexBytes(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// wantABIHex reconstructs the upstream ABI encoding (SPEC §12) directly
// from a vector's fields, independent of the CLI code under test, and
// returns it as lower-case 0x-prefixed hex.
func wantABIHex(t *testing.T, e vectorEntry) string {
	t.Helper()
	pkSeed := mustDecodeHex(t, e.PkSeed)
	pkRoot := mustDecodeHex(t, e.PkRoot)
	sig := mustDecodeHex(t, e.Signature)
	if len(pkSeed) != 32 {
		t.Fatalf("%s: pkSeed decodes to %d bytes, want 32", e.Name, len(pkSeed))
	}
	if len(pkRoot) != 32 {
		t.Fatalf("%s: pkRoot decodes to %d bytes, want 32", e.Name, len(pkRoot))
	}
	var seedArr, rootArr [32]byte
	copy(seedArr[:], pkSeed)
	copy(rootArr[:], pkRoot)
	return hex0x(abiEncode(seedArr, rootArr, sig))
}

// runCLI is a small convenience wrapper around run() for tests: it
// returns the exit code plus stdout/stderr as strings.
func runCLI(args ...string) (code int, stdout, stderr string) {
	var outBuf, errBuf bytes.Buffer
	code = run(args, &outBuf, &errBuf)
	return code, outBuf.String(), errBuf.String()
}

// ---------------------------------------------------------------------
// "vector" subcommand: byte-identical to the upstream reference tools.
// ---------------------------------------------------------------------

func TestVectorCommand(t *testing.T) {
	cases := []struct {
		params, file, name string
	}{
		{"C11", "c11.json", "c11_0xdeadbeef"},
		{"C10", "c10.json", "c10_0xdeadbeef"},
		{"C9", "c9.json", "c9_0xdeadbeef"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.params, func(t *testing.T) {
			e := loadVectorEntry(t, tc.file, tc.name)
			want := wantABIHex(t, e)

			code, stdout, stderr := runCLI("vector", "-params", tc.params, "-msg", e.Message)
			if code != exitOK {
				t.Fatalf("exit code = %d, want 0; stderr=%s", code, stderr)
			}
			got := strings.TrimSpace(stdout)
			if got != want {
				off := 0
				for off < len(got) && off < len(want) && got[off] == want[off] {
					off++
				}
				t.Fatalf("%s: vector output mismatch at char offset %d\ngot:  %s\nwant: %s", tc.name, off, got, want)
			}
		})
	}
}

// TestVectorCommandSlow covers C13 and C7, whose R-grind is expensive
// enough that they're gated behind SPHINCSMINUS_SLOW=1 like the root
// package's own slow tests (see CLAUDE.md).
func TestVectorCommandSlow(t *testing.T) {
	if os.Getenv("SPHINCSMINUS_SLOW") != "1" {
		t.Skip("skipping slow C13/C7 vector test; set SPHINCSMINUS_SLOW=1 to run it")
	}
	cases := []struct {
		params, file, name string
	}{
		{"C13", "c13.json", "c13_0xdeadbeef"},
		{"C7", "c7.json", "c7_0xdeadbeef"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.params, func(t *testing.T) {
			e := loadVectorEntry(t, tc.file, tc.name)
			want := wantABIHex(t, e)

			code, stdout, stderr := runCLI("vector", "-params", tc.params, "-msg", e.Message)
			if code != exitOK {
				t.Fatalf("exit code = %d, want 0; stderr=%s", code, stderr)
			}
			got := strings.TrimSpace(stdout)
			if got != want {
				t.Fatalf("%s: vector output mismatch\ngot:  %s\nwant: %s", tc.name, got, want)
			}
		})
	}
}

// ---------------------------------------------------------------------
// keygen -> sign -> verify roundtrip through the CLI.
// ---------------------------------------------------------------------

func TestKeygenSignVerifyRoundtrip(t *testing.T) {
	code, stdout, stderr := runCLI("keygen", "-params", "C11")
	if code != exitOK {
		t.Fatalf("keygen exit = %d, want 0; stderr=%s", code, stderr)
	}
	var kg keygenOutput
	if err := json.Unmarshal([]byte(stdout), &kg); err != nil {
		t.Fatalf("parse keygen JSON: %v\noutput: %s", err, stdout)
	}
	if kg.Params != "C11" {
		t.Fatalf("keygen params = %q, want C11", kg.Params)
	}
	if _, err := parseHexBytes(kg.PrivateKey); err != nil || len(mustDecodeHex(t, kg.PrivateKey)) != 64 {
		t.Fatalf("keygen privateKey malformed: %q", kg.PrivateKey)
	}
	if len(mustDecodeHex(t, kg.PublicKey)) != 32 {
		t.Fatalf("keygen publicKey malformed: %q", kg.PublicKey)
	}

	msg := "0x" + strings.Repeat("ab", 32)

	code, sigOut, stderr := runCLI("sign", "-params", "C11", "-sk", kg.PrivateKey, "-msg", msg)
	if code != exitOK {
		t.Fatalf("sign exit = %d, want 0; stderr=%s", code, stderr)
	}
	sigHex := strings.TrimSpace(sigOut)

	// Valid signature -> exit 0, "valid".
	code, out, stderr := runCLI("verify", "-params", "C11", "-pk", kg.PublicKey, "-msg", msg, "-sig", sigHex)
	if code != exitOK {
		t.Fatalf("verify (valid) exit = %d, want 0; stdout=%s stderr=%s", code, out, stderr)
	}
	if strings.TrimSpace(out) != "valid" {
		t.Fatalf("verify (valid) stdout = %q, want \"valid\"", out)
	}

	// Tampered signature -> exit 1, "invalid".
	sigBytes := mustDecodeHex(t, sigHex)
	sigBytes[0] ^= 0xff
	tamperedHex := hex0x(sigBytes)
	code, out, stderr = runCLI("verify", "-params", "C11", "-pk", kg.PublicKey, "-msg", msg, "-sig", tamperedHex)
	if code != exitInvalid {
		t.Fatalf("verify (tampered) exit = %d, want 1; stdout=%s stderr=%s", code, out, stderr)
	}
	if strings.TrimSpace(out) != "invalid" {
		t.Fatalf("verify (tampered) stdout = %q, want \"invalid\"", out)
	}

	// Bad hex -> exit 2.
	code, _, _ = runCLI("verify", "-params", "C11", "-pk", kg.PublicKey, "-msg", msg, "-sig", "0xzz")
	if code != exitUsage {
		t.Fatalf("verify (bad hex sig) exit = %d, want 2", code)
	}

	// Wrong-length -pk -> exit 2 (fixed-size field, unlike -sig).
	code, _, _ = runCLI("verify", "-params", "C11", "-pk", "0x1234", "-msg", msg, "-sig", sigHex)
	if code != exitUsage {
		t.Fatalf("verify (short -pk) exit = %d, want 2", code)
	}

	// Wrong-length -msg -> exit 2.
	code, _, _ = runCLI("verify", "-params", "C11", "-pk", kg.PublicKey, "-msg", "0x1234", "-sig", sigHex)
	if code != exitUsage {
		t.Fatalf("verify (short -msg) exit = %d, want 2", code)
	}

	// Wrong-length -sk on sign -> exit 2.
	code, _, _ = runCLI("sign", "-params", "C11", "-sk", "0x1234", "-msg", msg)
	if code != exitUsage {
		t.Fatalf("sign (short -sk) exit = %d, want 2", code)
	}
}

// TestSignWithKeyFile exercises "sign -key file.json" (the -key
// alternative to -sk), including params inference from the key file
// when -params is not given explicitly.
func TestSignWithKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.json")

	code, _, stderr := runCLI("keygen", "-params", "C11", "-out", keyPath)
	if code != exitOK {
		t.Fatalf("keygen -out exit = %d, want 0; stderr=%s", code, stderr)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat %s: %v", keyPath, err)
	}
	// Windows has no POSIX permission bits (os.Stat reports 0666 or 0444),
	// so the 0600 check is only meaningful on Unix-like systems.
	if perm := info.Mode().Perm(); runtime.GOOS != "windows" && perm != 0600 {
		t.Fatalf("keygen -out file mode = %o, want 0600", perm)
	}

	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read %s: %v", keyPath, err)
	}
	var kg keygenOutput
	if err := json.Unmarshal(data, &kg); err != nil {
		t.Fatalf("parse %s: %v", keyPath, err)
	}

	msg := "0x" + strings.Repeat("11", 32)

	// -key without an explicit -params: infers C11 from the file.
	code, sigOut, stderr := runCLI("sign", "-key", keyPath, "-msg", msg)
	if code != exitOK {
		t.Fatalf("sign -key exit = %d, want 0; stderr=%s", code, stderr)
	}
	sigHex := strings.TrimSpace(sigOut)

	code, out, stderr := runCLI("verify", "-params", "C11", "-pk", kg.PublicKey, "-msg", msg, "-sig", sigHex)
	if code != exitOK || strings.TrimSpace(out) != "valid" {
		t.Fatalf("verify after sign -key: code=%d out=%q stderr=%s", code, out, stderr)
	}

	// Mismatched explicit -params should be rejected.
	code, _, _ = runCLI("sign", "-key", keyPath, "-params", "C13", "-msg", msg)
	if code != exitUsage {
		t.Fatalf("sign -key with mismatched -params exit = %d, want 2", code)
	}
}

// TestVerifySigFile exercises "-sig @file", reading a raw signature from
// disk instead of hex on the command line.
func TestVerifySigFile(t *testing.T) {
	code, stdout, stderr := runCLI("keygen", "-params", "C11")
	if code != exitOK {
		t.Fatalf("keygen exit = %d, want 0; stderr=%s", code, stderr)
	}
	var kg keygenOutput
	if err := json.Unmarshal([]byte(stdout), &kg); err != nil {
		t.Fatalf("parse keygen JSON: %v", err)
	}

	msg := "0x" + strings.Repeat("22", 32)

	dir := t.TempDir()
	sigPath := filepath.Join(dir, "sig.bin")
	code, _, stderr = runCLI("sign", "-params", "C11", "-sk", kg.PrivateKey, "-msg", msg, "-o", sigPath)
	if code != exitOK {
		t.Fatalf("sign -o exit = %d, want 0; stderr=%s", code, stderr)
	}

	sigBytes, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatalf("read %s: %v", sigPath, err)
	}
	if len(sigBytes) == 0 {
		t.Fatalf("sign -o wrote an empty file")
	}
	// Sanity: the raw bytes must not be hex-encoded text.
	if _, err := hex.DecodeString(strings.TrimPrefix(string(sigBytes), "0x")); err == nil && bytes.ContainsAny(sigBytes, "\n") {
		t.Fatalf("sign -o appears to have written hex text instead of raw bytes")
	}

	code, out, stderr := runCLI("verify", "-params", "C11", "-pk", kg.PublicKey, "-msg", msg, "-sig", "@"+sigPath)
	if code != exitOK {
		t.Fatalf("verify -sig @file exit = %d, want 0; stdout=%s stderr=%s", code, out, stderr)
	}
	if strings.TrimSpace(out) != "valid" {
		t.Fatalf("verify -sig @file stdout = %q, want \"valid\"", out)
	}
}

// ---------------------------------------------------------------------
// params / help / misc.
// ---------------------------------------------------------------------

func TestParamsCommand(t *testing.T) {
	code, stdout, stderr := runCLI("params")
	if code != exitOK {
		t.Fatalf("params exit = %d, want 0; stderr=%s", code, stderr)
	}
	for _, want := range []string{"C7", "C9", "C10", "C11", "C13", "NAME", "SIG_BYTES"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("params output missing %q:\n%s", want, stdout)
		}
	}
}

func TestNoArgsUsage(t *testing.T) {
	code, _, stderr := runCLI()
	if code != exitUsage {
		t.Fatalf("no-args exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "Usage") && !strings.Contains(stderr, "Commands") {
		t.Errorf("no-args stderr does not look like usage text: %s", stderr)
	}
}

func TestUnknownCommand(t *testing.T) {
	code, _, stderr := runCLI("bogus")
	if code != exitUsage {
		t.Fatalf("unknown command exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "bogus") {
		t.Errorf("stderr does not mention the unknown command: %s", stderr)
	}
}

func TestPerSubcommandHelp(t *testing.T) {
	for _, cmd := range []string{"keygen", "sign", "verify", "vector", "params"} {
		code, _, stderr := runCLI(cmd, "-h")
		if code != exitOK {
			t.Errorf("%s -h exit = %d, want 0; stderr=%s", cmd, code, stderr)
		}
		if stderr == "" {
			t.Errorf("%s -h produced no usage output", cmd)
		}
	}
}

func TestCaseInsensitiveParams(t *testing.T) {
	code, _, stderr := runCLI("keygen", "-params", "c11")
	if code != exitOK {
		t.Fatalf("keygen -params c11 (lowercase) exit = %d, want 0; stderr=%s", code, stderr)
	}
}

func TestHexWithoutPrefix(t *testing.T) {
	msg := strings.Repeat("33", 32) // no "0x" prefix
	code, stdout, stderr := runCLI("vector", "-params", "C11", "-msg", msg)
	if code != exitOK {
		t.Fatalf("vector without 0x prefix exit = %d, want 0; stderr=%s", code, stderr)
	}
	if !strings.HasPrefix(strings.TrimSpace(stdout), "0x") {
		t.Fatalf("vector output should be 0x-prefixed: %s", stdout)
	}
}
