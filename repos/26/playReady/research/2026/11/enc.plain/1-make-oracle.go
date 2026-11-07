// make-oracle.go begin

// =============================================================================
//
// Stage 1 of the chain: build the nibble-oracle inputs used by 3-derive-map.
//
// WHY THIS EXISTS
//
//   3-derive-map measures the build's 16-entry nibble permutation by forcing
//   the mapped nibble to a constant value M against a license blob built for a
//   known key, and checking whether a known plaintext appears. That requires,
//   for every key nibble N in 0x0N for N in 0..f (excluding 0x00):
//
//       key_NN.pub    public key whose private scalar is nibble NN
//                     repeated 64 times
//       lic_NN.blob   licence blob addressed to that public key, whose
//                     plaintext content key / signature block contains
//                     the known sentinel "HELLO MICROSOFT!"
//
//   The permutation entry is recovered because decrypting a blob addressed to
//   key_NN with the unknown private key only succeeds if the forced mapped
//   nibble M satisfies MAP[M] = NN.
//
//   Nibble 0x00 is skipped here because scalar 0 is not a valid private key;
//   3-derive-map recovers that entry as the leftover permutation value.
//
// PIPELINE
//
//   make-oracle    ->  testdata/oracle/key_NN.pub, testdata/oracle/lic_NN.blob
//   2-decrypt-img  ->  testdata/wbtool_img.bin
//   3-derive-map   ->  testdata/oracle_map.json
//   4-derive-plain ->  testdata/extracted.enc.plain
//
// OUTPUTS   (all under testdata/, which is created on demand)
//
//   testdata/oracle/key_NN.pub     64 bytes, X||Y (no 0x04 prefix)
//   testdata/oracle/lic_NN.blob    128 bytes, C1.x||C1.y||C2.x||C2.y
//
// PROPERTIES
//
//   - key_NN.pub is DETERMINISTIC: same bytes on every run, every machine.
//     Byte-identical across runs, so a rebuilt oracle is verifiable with a
//     file hash.
//   - lic_NN.blob is NOT reproducible: it uses a random ephemeral scalar, so
//     the bytes differ on every run. Validity is proven instead by
//     3-derive-map reaching a live set and 4-derive-plain reaching pubkey MATCH.
//
// ORACLE PRIVATE SCALARS (for reference / manual checks)
//
//   nibble NN  ->  d = 0xNN repeated 64 times
//   For 0x0f that scalar (2^256-1) exceeds the group order N and is reduced
//   mod N for the scalar multiplication; the key *bytes* are still all 0x0f,
//   which is what the oracle needs.
//
// =============================================================================
package main

import (
   "crypto/rand"
   "fmt"
   "math/big"
   "os"
   "path/filepath"
   "strings"
)

// The licence plaintext: signature key = "HELLO MICROSOFT!", content key = zeros.
// 3-derive-map recovers the magic sequence as the 32-byte output shared by every
// licence XOR these bytes, so the licence blob has to land exactly on them.
const sentinelText = "HELLO MICROSOFT!"

// --- secp256r1 / NIST P-256 -------------------------------------------------
var (
   // y^2 = x^3 + A*x + B  over GF(P)
   P = mustHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF")
   B = mustHex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B")

   // order of the base point
   N = mustHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")

   three = big.NewInt(3)
   one   = big.NewInt(1)

   A = new(big.Int).Sub(P, three) // P - 3

   // base point
   G = &point{
      x: mustHex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
      y: mustHex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
   }
)

// concat32 renders each value as 32 big-endian bytes and concatenates them.
func concat32(vals ...*big.Int) []byte {
   out := make([]byte, 0, 32*len(vals))
   for _, v := range vals {
      out = append(out, pad32(v)...)
   }
   return out
}

// divMod returns num/den modulo P.
func divMod(num, den *big.Int) *big.Int {
   d := new(big.Int).Mod(den, P)
   inv := new(big.Int).ModInverse(d, P)
   if inv == nil {
      panic("field division by zero")
   }
   r := new(big.Int).Mul(num, inv)
   return r.Mod(r, P)
}

func fatal(format string, args ...any) {
   fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
   os.Exit(1)
}

func logf(format string, args ...any) {
   fmt.Printf(format+"\n", args...)
}

// --- main -------------------------------------------------------------------

func main() {
   // Every artefact this pipeline produces lives under testdata/. Keeping the
   // oracle beside the image it feeds means a run can never pick up a stale
   // copy from the current directory by accident.
   const data = "testdata"
   if err := os.MkdirAll(data, 0o755); err != nil {
      fatal("create %s: %v", data, err)
   }

   // Default testdata/oracle. An explicit argument still overrides it, so a
   // fresh set can be generated beside the existing one and compared before
   // swapping.
   out := filepath.Join(data, "oracle")
   if len(os.Args) > 1 {
      out = os.Args[1]
   }

   // --- sanity ---
   sent := append([]byte(sentinelText), make([]byte, 16)...)
   if len(sent) != 32 {
      fatal("sentinel is %d bytes, expected 32", len(sent))
   }
   mx := new(big.Int).SetBytes(sent)
   my := yFromX(mx)
   if my == nil || !onCurve(mx, my) {
      fatal("'HELLO MICROSOFT!' || 0^16 is not an x-coordinate on P-256")
   }
   m := &point{x: mx, y: my}

   if err := os.MkdirAll(out, 0o755); err != nil {
      fatal("create %s: %v", out, err)
   }
   if abs, err := filepath.Abs(out); err == nil {
      logf("output    %s", abs)
   } else {
      logf("output    %s", out)
   }
   logf("sentinel  X = %064x", mx)
   logf("          Y = %064x", my)
   logf("")

   var (
      keys  []*point
      blobs [][]byte
      seen  = make(map[string]int)  // reduced scalar -> nibble
      pubs  = make(map[string]bool) // emitted X||Y
   )

   for nib := 1; nib < 16; nib++ {
      // The oracle private scalar: this nibble repeated 64 times.
      raw, ok := new(big.Int).SetString(strings.Repeat(fmt.Sprintf("%x", nib), 64), 16)
      if !ok {
         fatal("nibble %02x: cannot parse scalar", nib)
      }
      k := new(big.Int).Mod(raw, N)
      if k.Sign() == 0 {
         fatal("nibble %02x reduces to a zero scalar", nib)
      }
      if prev, dup := seen[k.String()]; dup {
         fatal("nibble %02x collides with %02x after reduction", nib, prev)
      }
      seen[k.String()] = nib

      q := mul(G, k)
      if q == nil || !onCurve(q.x, q.y) {
         fatal("nibble %02x produced an invalid public point", nib)
      }

      // --- key file: X||Y, no 0x04 prefix, exactly what .sig.pub/.enc.pub use
      pub := concat32(q.x, q.y)
      if len(pub) != 0x40 {
         fatal("nibble %02x: pubkey is %d bytes", nib, len(pub))
      }
      if pubs[string(pub)] {
         fatal("nibble %02x duplicates an earlier public key", nib)
      }
      pubs[string(pub)] = true
      if err := os.WriteFile(filepath.Join(out, fmt.Sprintf("key_%02x.pub", nib)), pub, 0o644); err != nil {
         fatal("write key_%02x.pub: %v", nib, err)
      }
      keys = append(keys, q)

      // --- licence blob: ECIES  C1 = r*G,  C2 = M + r*Q
      // Decryption with scalar k gives C2 - k*C1 = M, so the plaintext point's
      // X-coordinate is the sentinel and the routine's output is SENT XOR magic.
      r := randScalar()
      c1 := mul(G, r)
      c2 := add(m, mul(q, r))
      if c1 == nil || c2 == nil {
         fatal("nibble %02x: degenerate ECIES point", nib)
      }
      blob := concat32(c1.x, c1.y, c2.x, c2.y)
      if len(blob) != 0x80 {
         fatal("nibble %02x: blob is %d bytes", nib, len(blob))
      }
      if err := os.WriteFile(filepath.Join(out, fmt.Sprintf("lic_%02x.blob", nib)), blob, 0o644); err != nil {
         fatal("write lic_%02x.blob: %v", nib, err)
      }
      blobs = append(blobs, blob)

      // --- round-trip: decrypt with the oracle scalar and require the sentinel
      rec := add(c2, mul(c1, new(big.Int).Sub(N, k)))
      if rec == nil || rec.x.Cmp(m.x) != 0 || rec.y.Cmp(m.y) != 0 {
         fatal("nibble %02x: round-trip did not recover the sentinel point", nib)
      }

      note := ""
      if raw.Cmp(N) >= 0 {
         note = "  (scalar 2^256-1 > N, reduced; key bytes still all 0f)"
      }
      logf("%02x  d = %064x%s", nib, k, note)
      logf("    X %064x", q.x)
      logf("    Y %064x", q.y)
      logf("    key 0x40 bytes  blob 0x80 bytes  round-trip OK")
   }

   // --- final invariants, because a bad oracle silently produces a wrong MAP
   if len(pubs) != 15 {
      fatal("only %d distinct public keys, expected 15", len(pubs))
   }
   uniq := make(map[string]bool, len(blobs))
   for _, b := range blobs {
      uniq[string(b)] = true
   }
   if len(uniq) != 15 {
      fatal("only %d distinct blobs, expected 15", len(uniq))
   }

   logf("")
   logf("generated %d/15 key+licence pairs in %s", len(keys), out)
   logf("key_NN.pub is deterministic; lic_NN.blob is not (random ephemeral scalar).")
}

// mustHex parses a hex constant, panicking on malformed input (compile-time
// data, so a failure here is a programming error).
func mustHex(s string) *big.Int {
   v, ok := new(big.Int).SetString(s, 16)
   if !ok {
      panic("bad hex constant: " + s)
   }
   return v
}

// onCurve reports whether (x, y) satisfies the curve equation.
func onCurve(x, y *big.Int) bool {
   if x.Sign() < 0 || x.Cmp(P) >= 0 || y.Sign() < 0 || y.Cmp(P) >= 0 {
      return false
   }
   rhs := new(big.Int).Exp(x, three, P)
   rhs.Add(rhs, new(big.Int).Mul(A, x))
   rhs.Add(rhs, B)

   lhs := new(big.Int).Mul(y, y)
   lhs.Sub(lhs, rhs)
   lhs.Mod(lhs, P)
   return lhs.Sign() == 0
}

// --- helpers ----------------------------------------------------------------

// pad32 renders v as a big-endian 32-byte field element.
func pad32(v *big.Int) []byte {
   b := v.Bytes()
   if len(b) > 32 {
      panic("field element wider than 32 bytes")
   }
   out := make([]byte, 32)
   copy(out[32-len(b):], b)
   return out
}

// randScalar draws a uniform non-zero scalar mod N.
func randScalar() *big.Int {
   buf := make([]byte, 32)
   for {
      if _, err := rand.Read(buf); err != nil {
         fatal("read random: %v", err)
      }
      r := new(big.Int).Mod(new(big.Int).SetBytes(buf), N)
      if r.Sign() != 0 {
         return r
      }
   }
}

// yFromX returns the even-square-root Y for x, or nil if x is not on the curve.
func yFromX(x *big.Int) *big.Int {
   // rhs = x^3 + A*x + B (mod P)
   rhs := new(big.Int).Exp(x, three, P)
   rhs.Add(rhs, new(big.Int).Mul(A, x))
   rhs.Add(rhs, B)
   rhs.Mod(rhs, P)

   // P = 3 mod 4, so this is the square root
   e := new(big.Int).Add(P, one)
   e.Rsh(e, 2) // (P+1)/4
   y := new(big.Int).Exp(rhs, e, P)

   // no square root: x is not on the curve
   chk := new(big.Int).Mul(y, y)
   chk.Sub(chk, rhs)
   chk.Mod(chk, P)
   if chk.Sign() != 0 {
      return nil
   }

   // canonical (even) root
   if y.Bit(0) == 1 {
      y.Sub(P, y)
   }
   return y
}

// --- affine point arithmetic ------------------------------------------------

// point is an affine point on P-256; a nil *point is the point at infinity.
type point struct {
   x, y *big.Int
}

// add performs affine point addition on P-256.
func add(p, q *point) *point {
   if p == nil {
      return q
   }
   if q == nil {
      return p
   }

   var lam *big.Int
   if p.x.Cmp(q.x) == 0 {
      sum := new(big.Int).Add(p.y, q.y)
      sum.Mod(sum, P)
      if sum.Sign() == 0 {
         return nil // p == -q
      }
      // doubling: lam = (3x^2 + A) / 2y
      num := new(big.Int).Mul(p.x, p.x)
      num.Mul(num, three)
      num.Add(num, A)
      den := new(big.Int).Lsh(p.y, 1)
      lam = divMod(num, den)
   } else {
      // addition: lam = (y2 - y1) / (x2 - x1)
      num := new(big.Int).Sub(q.y, p.y)
      den := new(big.Int).Sub(q.x, p.x)
      lam = divMod(num, den)
   }

   x3 := new(big.Int).Mul(lam, lam)
   x3.Sub(x3, p.x)
   x3.Sub(x3, q.x)
   x3.Mod(x3, P)

   y3 := new(big.Int).Sub(p.x, x3)
   y3.Mul(y3, lam)
   y3.Sub(y3, p.y)
   y3.Mod(y3, P)

   return &point{x: x3, y: y3}
}

// mul is double-and-add scalar multiplication; k is taken mod N.
func mul(pt *point, k *big.Int) *point {
   var r *point
   kk := new(big.Int).Mod(k, N)
   for kk.Sign() != 0 {
      if kk.Bit(0) == 1 {
         r = add(r, pt)
      }
      pt = add(pt, pt)
      kk.Rsh(kk, 1)
   }
   return r
}

// make-oracle.go end
