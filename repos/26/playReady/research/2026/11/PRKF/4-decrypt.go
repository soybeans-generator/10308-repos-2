// 4-decrypt.go begin
//go:build windows

// Decrypts a PlayReady signing key (extracted.sig.prv -> extracted.sig.plain).
//
// Takes no arguments. Input, output and public-key names are fixed to the
// ones 2-extract-keys.go produces. The output is written only after every
// available check passes.
//
// # VERSION SUPPORT
//
// Only ONE value differs between DLL builds: the RVA of the heap descriptor
// holding the signing-key routine. It comes from prsubs.json, keyed by the
// DLL sha256 and produced by 3-find-sub.go, which does not use sample keys.
// This program refuses to run if the cache does not match the DLL.
//
// Everything else is hardcoded because it cannot drift with the DLL:
//
//   - op=3 and the WarbirdCallArgs layout are a kernel ABI. The DLL and the
//     running kernel must agree on them, so neither can change unilaterally.
//   - The routine's own argument struct is packed (it reads its output
//     pointer unaligned at +0x14), and packed layout is fixed by source and
//     invariant under recompilation.
//   - size == 0x20 is the P-256 private scalar length, and the routine tests
//     it itself with `cmp dword ptr [rcx+10h], 20h`.
//   - 0x34 is the size of the kernel's call-args struct.
//
// prsubs.json is read from the CURRENT DIRECTORY, so run this from the same
// directory 3-find-sub.go was run in.
//
// # VERIFICATION
//
// The check is cryptographic and needs no secret reference: the plaintext d,
// read big-endian, must satisfy d*G == Q, where Q is the P-256 public key
// that 2-extract-keys.go wrote next to the ciphertext. A wrong descriptor, a
// wrong output offset, a wrong argument layout or a wrong input file cannot
// produce a scalar whose public point lands on Q. Cost: a few milliseconds.
//
// This single check subsumes scalar-range validation: a d outside [1, n-1]
// cannot yield Q, so no separate range test is performed.
//
// Failure is loud, never silent:
//
//   wrong desc_va     -> NTSTATUS 0xC0000095 (INTEGER_OVERFLOW)
//   wrong arg layout  -> status dword 0x80070057 (E_INVALIDARG) and an
//                        unwritten output buffer; 3-find-sub.go would also
//                        report zero accepted descriptors
//   output == input   -> descriptor for the wrong routine
//   d*G != sig.pub    -> descriptor, argument layout or input is wrong
package main

import (
   "bytes"
   "crypto/rand"
   "crypto/sha256"
   "encoding/binary"
   "encoding/hex"
   "encoding/json"
   "errors"
   "fmt"
   "math/big"
   "os"
   "runtime"
   "syscall"
   "unsafe"
)

const (
   dllPath = `C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll`

   srcName = "extracted.sig.prv"   // written by 2-extract-keys.go
   pubName = "extracted.sig.pub"   // written by 2-extract-keys.go
   dstName = "extracted.sig.plain" // 32-byte plaintext scalar

   // keyLen is the P-256 private scalar length, and the size the routine
   // accepts.
   keyLen = 0x20

   // outOff is where the routine reads its output pointer from args+0x14 -
   // i.e. struct+0x24, because the args it sees begin 0x10 into the kernel's
   // WarbirdCallArgs. The read is unaligned, so this value cannot be
   // inferred from alignment.
   outOff = 0x24

   // warbirdOp is op=3 (WbHeapExecuteCall); argsLen is the size of the
   // kernel's call-args struct.
   warbirdOp = 3
   argsLen   = 0x34
)

// ---- P-256 domain parameters ---------------------------------------------

var (
   p256P  = mustHex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
   p256A  = new(big.Int).Sub(p256P, big.NewInt(3))
   p256B  = mustHex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")
   p256Gx = mustHex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
   p256Gy = mustHex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")

   // (p+1)/4; p == 3 (mod 4), so a square root is one exponentiation.
   p256SqrtExp = new(big.Int).Rsh(new(big.Int).Add(p256P, big.NewInt(1)), 2)
)

// ---- the kernel call -----------------------------------------------------

// decryptSigningKey decrypts a 32-byte obfuscated PlayReady signing key.
//
//   prvPath : file holding the 32-byte *.sig.prv component
//   outPath : optional path for the 32-byte plaintext key ("" writes nothing)
//
// It returns the 32-byte plaintext private key.
func decryptSigningKey(prvPath, outPath string) ([]byte, error) {
   rec, err := loadPrsubs()
   if err != nil {
      return nil, err
   }

   dll, err := syscall.LoadDLL(dllPath)
   if err != nil {
      return nil, fmt.Errorf("loading %s failed, err %v", dllPath, err)
   }
   base := uintptr(dll.Handle)

   ntdll, err := syscall.LoadDLL("ntdll.dll")
   if err != nil {
      return nil, err
   }
   ntQuerySystemInformation, err := ntdll.FindProc("NtQuerySystemInformation")
   if err != nil {
      return nil, err
   }

   enc, err := os.ReadFile(prvPath)
   if err != nil {
      return nil, err
   }
   if len(enc) != keyLen {
      return nil, fmt.Errorf("%s: expected %d bytes, got %d", prvPath, keyLen, len(enc))
   }

   // A random fill proves the routine actually wrote to the output buffer;
   // a fixed sentinel could collide with real key material.
   fill := make([]byte, keyLen)
   if _, err := rand.Read(fill); err != nil {
      return nil, err
   }
   keyBuf := append(make([]byte, 0, keyLen), enc...) // the routine gets its own copy
   status := make([]byte, 0x10)                      // zero-filled
   out := append(make([]byte, 0, keyLen), fill...)
   args := make([]byte, argsLen)

   // Kernel WarbirdCallArgs for op=3 (WbHeapExecuteCall). The arguments the
   // routine itself sees begin at +0x10, which is why its documented +0x14
   // output field lands at +0x24 here:
   //
   //   +0x00  op = 3
   //   +0x08  descriptor address
   //   +0x10  -> status dword   (routine's +0x00)
   //   +0x18  -> 32-byte key    (routine's +0x08)
   //   +0x20  u32 key size      (routine's +0x10)
   //   +0x24  -> output buffer  (routine's +0x14)
   binary.LittleEndian.PutUint64(args[0x00:], warbirdOp)
   binary.LittleEndian.PutUint64(args[0x08:], uint64(base)+rec.DescVA)
   binary.LittleEndian.PutUint64(args[0x10:], uint64(uintptr(unsafe.Pointer(&status[0]))))
   binary.LittleEndian.PutUint64(args[0x18:], uint64(uintptr(unsafe.Pointer(&keyBuf[0]))))
   binary.LittleEndian.PutUint32(args[0x20:], keyLen)
   binary.LittleEndian.PutUint64(args[outOff:], uint64(uintptr(unsafe.Pointer(&out[0]))))

   // SystemExtendedProcessInformation (0xB9) is the Warbird call gate.
   // NTSTATUS comes back in r1; the upper half of the register is garbage.
   st, _, _ := ntQuerySystemInformation.Call(
      0xB9,
      uintptr(unsafe.Pointer(&args[0])),
      argsLen,
      0,
   )
   runtime.KeepAlive(args)
   runtime.KeepAlive(status)
   runtime.KeepAlive(keyBuf)
   runtime.KeepAlive(out)

   if st32 := uint32(st); st32 != 0 {
      msg := fmt.Sprintf("NtQuerySystemInformation -> %#010x", st32)
      if st32 == 0xC0000095 {
         msg += " (INTEGER_OVERFLOW: desc_va is wrong for this build)"
      }
      return nil, errors.New(msg)
   }

   if !bytes.Equal(status[:4], []byte{0, 0, 0, 0}) {
      return nil, fmt.Errorf("routine returned %s - the argument layout no "+
         "longer matches this build; re-run 3-find-sub.go",
         hex.EncodeToString(status[:4]))
   }

   res := out
   if bytes.Equal(res, fill) {
      return nil, errors.New("output buffer untouched - out_off is wrong")
   }
   if bytes.Equal(res, enc) {
      return nil, errors.New("output equals input - desc_va is the wrong routine")
   }

   if outPath != "" {
      if err := os.WriteFile(outPath, res, 0o666); err != nil {
         return nil, err
      }
   }
   return res, nil
}

func isFile(p string) bool {
   fi, err := os.Stat(p)
   return err == nil && fi.Mode().IsRegular()
}

// ---- main ----------------------------------------------------------------

func main() {
   if err := run(os.Args[1:]); err != nil {
      fmt.Fprintln(os.Stderr, err)
      os.Exit(1)
   }
}

func mustHex(s string) *big.Int {
   n, ok := new(big.Int).SetString(s, 16)
   if !ok {
      panic("bad hex constant " + s)
   }
   return n
}

// p256RHS returns x^3 + a*x + b mod p.
func p256RHS(x *big.Int) *big.Int {
   t := new(big.Int).Mul(x, x)
   t.Mul(t, x)
   t.Mod(t, p256P)
   t.Add(t, new(big.Int).Mul(p256A, x))
   t.Add(t, p256B)
   t.Mod(t, p256P)
   return t
}

func pointsEqual(p1, p2 *point) bool {
   if p1 == nil || p2 == nil {
      return p1 == nil && p2 == nil
   }
   return p1.x.Cmp(p2.x) == 0 && p1.y.Cmp(p2.y) == 0
}

func run(argv []string) error {
   // ---- arguments: nothing positional, nothing optional --------------
   if len(argv) > 0 {
      return fmt.Errorf("unexpected argument %q: this program takes no arguments",
         argv[0])
   }

   if !isFile(srcName) {
      return fmt.Errorf("missing input: %s\n  run 2-extract-keys.go first", srcName)
   }
   if !isFile(pubName) {
      return fmt.Errorf("missing public key: %s\n"+
         "  run 2-extract-keys.go first", pubName)
   }

   // ---- decrypt ------------------------------------------------------
   got, err := decryptSigningKey(srcName, "")
   if err != nil {
      return err
   }
   fmt.Printf("%s (%d bytes)\n", srcName, keyLen)
   fmt.Printf("plaintext %s\n", hex.EncodeToString(got))

   // ---- validation: d*G must equal the published public key ----------
   raw, err := os.ReadFile(pubName)
   if err != nil {
      return err
   }
   want, err := parsePubkey(raw)
   if err != nil {
      return fmt.Errorf("%s: %v", pubName, err)
   }

   if !pointsEqual(pubkeyOf(new(big.Int).SetBytes(got)), want) {
      return fmt.Errorf("d*G != %s - the plaintext is not the private key for\n"+
         "that public key; the descriptor, the argument layout or the\n"+
         "input file is wrong; nothing was written", pubName)
   }
   fmt.Printf("[ OK ] d*G == %s\n", pubName)
   fmt.Printf("       Q = (%064x,\n            %064x)\n", want.x, want.y)

   // ---- write --------------------------------------------------------
   if err := os.WriteFile(dstName, got, 0o666); err != nil {
      return err
   }
   fmt.Printf("\nwrote %s (%d bytes)\n", dstName, len(got))
   return nil
}

func short(s string) string {
   if len(s) > 16 {
      return s[:16]
   }
   if s == "" {
      return "?"
   }
   return s
}

// ---- P-256 arithmetic, for validating the plaintext ----------------------

// point is an affine P-256 point; nil is the point at infinity.
type point struct{ x, y *big.Int }

// ecAdd is affine point addition on P-256.
func ecAdd(p1, p2 *point) *point {
   if p1 == nil {
      return p2
   }
   if p2 == nil {
      return p1
   }
   x1, y1 := p1.x, p1.y
   x2, y2 := p2.x, p2.y

   var lam *big.Int
   if x1.Cmp(x2) == 0 {
      sum := new(big.Int).Add(y1, y2)
      sum.Mod(sum, p256P)
      if sum.Sign() == 0 {
         return nil // P + (-P), and y == 0
      }
      // lambda = (3*x1*x1 + a) / (2*y1)
      num := new(big.Int).Mul(x1, x1)
      num.Mul(num, big.NewInt(3))
      num.Add(num, p256A)

      den := new(big.Int).Lsh(y1, 1) // 2*y1
      den.Mod(den, p256P)

      lam = num.Mul(num, new(big.Int).ModInverse(den, p256P))
      lam.Mod(lam, p256P)
   } else {
      // lambda = (y2 - y1) / (x2 - x1)
      num := new(big.Int).Sub(y2, y1)
      den := new(big.Int).Sub(x2, x1)
      den.Mod(den, p256P)

      lam = num.Mul(num, new(big.Int).ModInverse(den, p256P))
      lam.Mod(lam, p256P)
   }

   x3 := new(big.Int).Mul(lam, lam)
   x3.Sub(x3, x1)
   x3.Sub(x3, x2)
   x3.Mod(x3, p256P)

   y3 := new(big.Int).Sub(x1, x3)
   y3.Mul(y3, lam)
   y3.Sub(y3, y1)
   y3.Mod(y3, p256P)

   return &point{x3, y3}
}

// ecMul is right-to-left double-and-add; ~384 modular inversions for k < 2^256.
func ecMul(k *big.Int, pt *point) *point {
   k = new(big.Int).Set(k) // never mutate the caller's scalar
   var acc *point
   for k.Sign() > 0 {
      if k.Bit(0) == 1 {
         acc = ecAdd(acc, pt)
      }
      pt = ecAdd(pt, pt)
      k.Rsh(k, 1)
   }
   return acc
}

// parsePubkey decodes an uncompressed (65B), raw (64B) or compressed (33B)
// P-256 point, and verifies that it really lies on the curve.
func parsePubkey(blob []byte) (*point, error) {
   var x, y *big.Int

   switch {
   case len(blob) == 65 && blob[0] == 0x04:
      x = new(big.Int).SetBytes(blob[1:33])
      y = new(big.Int).SetBytes(blob[33:65])
   case len(blob) == 64:
      x = new(big.Int).SetBytes(blob[:32])
      y = new(big.Int).SetBytes(blob[32:])
   case len(blob) == 33 && (blob[0] == 0x02 || blob[0] == 0x03):
      x = new(big.Int).SetBytes(blob[1:])
      y = new(big.Int).Exp(p256RHS(x), p256SqrtExp, p256P) // p == 3 (mod 4)
      if y.Bit(0) != uint(blob[0]&1) {
         y.Sub(p256P, y)
      }
   default:
      prefix := blob
      if len(prefix) > 1 {
         prefix = prefix[:1]
      }
      return nil, fmt.Errorf("%d bytes, prefix %s - not a P-256 point encoding",
         len(blob), hex.EncodeToString(prefix))
   }

   if x.Cmp(p256P) >= 0 || y.Cmp(p256P) >= 0 {
      return nil, errors.New("coordinate outside the field")
   }
   lhs := new(big.Int).Mul(y, y)
   lhs.Mod(lhs, p256P)
   if lhs.Cmp(p256RHS(x)) != 0 {
      return nil, errors.New("point is not on the P-256 curve")
   }
   if x.Sign() == 0 && y.Sign() == 0 {
      return nil, errors.New("point at infinity")
   }
   return &point{x, y}, nil
}

func pubkeyOf(d *big.Int) *point {
   return ecMul(d, &point{p256Gx, p256Gy})
}

// ---- prsubs.json ---------------------------------------------------------

type prsubsRecord struct {
   SHA256 string `json:"sha256"`
   DescVA uint64 `json:"desc_va"`
}

// loadPrsubs loads and validates the build-specific descriptor RVA.
func loadPrsubs() (*prsubsRecord, error) {
   dll, err := os.ReadFile(dllPath)
   if err != nil {
      return nil, err
   }
   sum := sha256.Sum256(dll)
   sha := hex.EncodeToString(sum[:])

   if !isFile("prsubs.json") {
      return nil, errors.New("no prsubs.json in the current directory - " +
         "run 3-find-sub.go here first")
   }
   raw, err := os.ReadFile("prsubs.json")
   if err != nil {
      return nil, err
   }
   var rec prsubsRecord
   if err := json.Unmarshal(raw, &rec); err != nil {
      return nil, fmt.Errorf("prsubs.json: %v", err)
   }

   if rec.SHA256 != sha {
      return nil, fmt.Errorf("prsubs.json was built for a different DLL\n"+
         "  cache : %s...\n"+
         "  actual: %s...\n"+
         "  re-run 3-find-sub.go", short(rec.SHA256), short(sha))
   }
   if rec.DescVA == 0 {
      return nil, errors.New("cache has no desc_va - re-run 3-find-sub.go")
   }
   return &rec, nil
}

// 4-decrypt.go end
