// oracle.go begin
//go:build windows

// prkf -4: build the nibble-oracle inputs that -6 measures the permutation with.
//
// WHY THIS EXISTS
//
//   nibblemap forces the mapped nibble to a constant M and decrypts a licence
//   blob built for a known key, checking whether the sentinel plaintext
//   "HELLO MICROSOFT!" appears. The forced value is the real nibble only when
//   MAP[M] equals the key's nibble, so one live set over all 15 licences reads
//   out the whole table. That needs, for each key nibble N in 0x01..0x0f:
//
//       key_NN.pub    public key whose private scalar has every nibble = N
//       lic_NN.blob   ECIES blob for that key whose plaintext is the sentinel
//
//   Nibble 0x00 is skipped: scalar 0 is not a valid private key, and -6
//   recovers that entry as the leftover permutation value.
//
// THE SCALAR IS NIBBLES, NOT BYTES
//
//   Forcing the table to a constant M makes every NIBBLE of the routine's
//   derived scalar equal to M, so that scalar is 32 bytes of 0x11*M - not 32
//   bytes of 0x0M. The oracle key has to match it exactly, or no forced value
//   ever reproduces the key: -6 then sees 16 unrelated outputs per licence and
//   no shared sentinel. For N = 0x0f this is 2^256-1.
//
// PIPELINE
//
//   prkf -4  ->  oracle/key_NN.pub, oracle/lic_NN.blob      (this step)
//   prkf -5  ->  wbtool_img.bin
//   prkf -6  ->  oracle_map.json
//   prkf -7  ->  extracted.enc.plain
//
// USAGE   prkf -4. No flags of its own; every path is a manifest entry in main.go.
//
// OUTPUTS   (under oracleDir, created on demand)
//
//   key_NN.pub     64 bytes, X||Y (no 0x04 prefix)
//   lic_NN.blob    128 bytes, C1.x||C1.y||C2.x||C2.y
//
// PROPERTIES
//
//   - key_NN.pub is DETERMINISTIC: byte-identical on every run and machine, so
//     a rebuilt oracle is verifiable against a saved copy.
//   - lic_NN.blob is NOT: it uses a random ephemeral scalar. Validity is proven
//     instead by -6 reaching a live set and -7 reaching pubkey MATCH.
//
// ORACLE PRIVATE SCALARS   nibble NN -> d = NN repeated 64 hex digits, i.e.
//
//   32 bytes of 0x11*NN. For 0x0f that is 2^256-1, which exceeds the group
//   order; the routine computes the unreduced value and the two agree mod N.
//
// CURVE ARITHMETIC
//
//   filippo.io/nistec does the point work: ScalarBaseMult, ScalarMult, Add and
//   SetBytes (which validates on-curve, so nothing calls IsOnCurve) - the
//   replacement crypto/elliptic's deprecation points at. Only the sentinel's
//   y-coordinate needs anything else: big.Int.ModSqrt, since P = 3 mod 4.
//
// EXIT CODES / GLOBALS
//
//   Nothing here calls os.Exit: stageMakeOracle returns 1 for every fatal
//   condition, so main owns the only termination in the program. moParams is
//   the only global, because elliptic.P256().Params() is called three times -
//   for N, for P, and for B in the sentinel's curve equation. The constant 3
//   appears once and is a local, next to that equation.
package main

import (
   "bytes"
   "crypto/elliptic"
   "crypto/rand"
   "fmt"
   "math/big"
   "os"
   "path/filepath"

   "filippo.io/nistec"
)

var (
   moParams = elliptic.P256().Params()
   moN      = moParams.N
   moP      = moParams.P
)

// moFail reports a fatal condition on stderr and yields exit code 1. It returns
// the code rather than exiting so stageMakeOracle has one exit point.
func moFail(format string, args ...any) int {
   fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
   return 1
}

// moRandScalar draws a uniform non-zero scalar mod N.
func moRandScalar() (*big.Int, error) {
   for {
      k, err := rand.Int(rand.Reader, moN)
      if err != nil {
         return nil, fmt.Errorf("read random: %w", err)
      }
      if k.Sign() != 0 {
         return k, nil
      }
   }
}

// moScalar renders v as the 32-byte big-endian scalar nistec expects. FillBytes
// rather than Bytes: a scalar with leading zero bytes is still 32 bytes long,
// and the point routines want a fixed-width input.
func moScalar(v *big.Int) []byte {
   b := make([]byte, 32)
   v.FillBytes(b)
   return b
}

// moXY returns a point as X||Y, the 64-byte form every PlayReady key file uses.
// An infinity result - possible only if a sum cancels - has no 65-byte encoding
// and is an error here rather than silently written as 64 zero bytes.
func moXY(nib int, what string, p *nistec.P256Point) ([]byte, error) {
   b := p.Bytes()
   if len(b) != 65 || b[0] != 4 {
      return nil, fmt.Errorf("nibble %02x: %s is the identity", nib, what)
   }
   return b[1:], nil
}

// --- stage entry point ------------------------------------------------------

func stageMakeOracle() int {
   out := oracleDir

   // Every artefact this pipeline produces lives under outDir. Keeping the
   // oracle beside the image it feeds means a run can never pick up a stale
   // copy from the current directory by accident.
   if err := os.MkdirAll(outDir, 0o755); err != nil {
      return moFail("create %s: %v", outDir, err)
   }

   // --- sanity: the sentinel has to be an x-coordinate on the curve.
   // The licence plaintext: signature key = "HELLO MICROSOFT!", content key =
   // zeros. -6 recovers the magic sequence as the 32-byte output shared by
   // every licence XOR these bytes, so the licence blob has to land exactly on
   // them.
   sent := append([]byte("HELLO MICROSOFT!"), make([]byte, 16)...)
   if len(sent) != 32 {
      return moFail("sentinel is %d bytes, expected 32", len(sent))
   }
   mx := new(big.Int).SetBytes(sent)

   // y^2 = x^3 + a*x + b, with a = -3. P = 3 mod 4, so ModSqrt is the square
   // root. SetBytes below is what proves the pair is really on the curve.
   three := big.NewInt(3)
   rhs := new(big.Int).Exp(mx, three, moP)
   rhs.Sub(rhs, new(big.Int).Mul(three, mx))
   rhs.Add(rhs, moParams.B)
   rhs.Mod(rhs, moP)
   my := new(big.Int).ModSqrt(rhs, moP)
   if my == nil {
      return moFail("'HELLO MICROSOFT!' || 0^16 is not an x-coordinate on P-256")
   }
   // canonical (even) root, so the Y in the log is stable across runs
   if my.Bit(0) == 1 {
      my.Sub(moP, my)
   }

   enc := make([]byte, 65)
   enc[0] = 4
   mx.FillBytes(enc[1:33])
   my.FillBytes(enc[33:])
   m, err := nistec.NewP256Point().SetBytes(enc)
   if err != nil {
      return moFail("sentinel point rejected by nistec: %v", err)
   }

   if err := os.MkdirAll(out, 0o755); err != nil {
      return moFail("create %s: %v", out, err)
   }
   if abs, err := filepath.Abs(out); err == nil {
      fmt.Printf("output    %s\n", abs)
   } else {
      fmt.Printf("output    %s\n", out)
   }
   fmt.Printf("sentinel  X = %064x\n", mx)
   fmt.Printf("          Y = %064x\n", my)
   fmt.Printf("\n")

   // Distinct public keys are the oracle's whole output: a collision would
   // silently overwrite one nibble's key with another's.
   pubs := make(map[string]bool)

   for nib := 1; nib < 16; nib++ {
      // The oracle private scalar: nibble NN repeated 64 times, which is 32
      // bytes of 0x11*NN. Not 32 bytes of 0x0N: the forced table makes every
      // NIBBLE of the derived scalar equal to the forced value, so a byte is
      // two of them. See the note at the top of the file.
      raw := new(big.Int).SetBytes(bytes.Repeat([]byte{byte(nib * 0x11)}, 32))
      k := new(big.Int).Mod(raw, moN)
      if k.Sign() == 0 {
         return moFail("nibble %02x reduces to a zero scalar", nib)
      }

      q, err := nistec.NewP256Point().ScalarBaseMult(moScalar(k))
      if err != nil {
         return moFail("nibble %02x: ScalarBaseMult: %v", nib, err)
      }

      // --- key file: X||Y, no 0x04 prefix, exactly what .sig.pub/.enc.pub use
      pub, err := moXY(nib, "public key", q)
      if err != nil {
         return moFail("%v", err)
      }
      if pubs[string(pub)] {
         return moFail("nibble %02x duplicates an earlier public key", nib)
      }
      pubs[string(pub)] = true
      if err := os.WriteFile(filepath.Join(out, fmt.Sprintf("key_%02x.pub", nib)), pub, 0o644); err != nil {
         return moFail("write key_%02x.pub: %v", nib, err)
      }

      // --- licence blob: ECIES  C1 = r*G,  C2 = M + r*Q
      // Decryption with scalar k gives C2 - k*C1 = M, so the plaintext point's
      // X-coordinate is the sentinel and the routine's output is SENT XOR magic.
      r, err := moRandScalar()
      if err != nil {
         return moFail("%v", err)
      }
      c1, err := nistec.NewP256Point().ScalarBaseMult(moScalar(r))
      if err != nil {
         return moFail("nibble %02x: C1 = r*G: %v", nib, err)
      }
      rq, err := nistec.NewP256Point().ScalarMult(q, moScalar(r))
      if err != nil {
         return moFail("nibble %02x: r*Q: %v", nib, err)
      }
      c2 := nistec.NewP256Point().Add(m, rq)

      c1b, err := moXY(nib, "C1", c1)
      if err != nil {
         return moFail("%v", err)
      }
      c2b, err := moXY(nib, "C2", c2)
      if err != nil {
         return moFail("%v", err)
      }
      blob := append(append([]byte(nil), c1b...), c2b...)
      if len(blob) != 0x80 {
         return moFail("nibble %02x: blob is %d bytes", nib, len(blob))
      }
      if err := os.WriteFile(filepath.Join(out, fmt.Sprintf("lic_%02x.blob", nib)), blob, 0o644); err != nil {
         return moFail("write lic_%02x.blob: %v", nib, err)
      }

      // --- round-trip: C2 - k*C1 must be the sentinel point. The routine uses
      // the unreduced scalar, which is congruent to k mod N, so this check
      // covers what the routine will actually compute even for nibble 0x0f.
      negK := new(big.Int).Sub(moN, k)
      kc1, err := nistec.NewP256Point().ScalarMult(c1, moScalar(negK))
      if err != nil {
         return moFail("nibble %02x: -k*C1: %v", nib, err)
      }
      rec := nistec.NewP256Point().Add(c2, kc1)
      if !bytes.Equal(rec.Bytes(), m.Bytes()) {
         return moFail("nibble %02x: round-trip did not recover the sentinel point", nib)
      }

      note := ""
      if raw.Cmp(moN) >= 0 {
         note = "  (scalar 2^256-1 > N, reduced; nibbles still all 0f)"
      }
      fmt.Printf("%02x  d = %064x%s\n", nib, k, note)
      fmt.Printf("    X %064x\n", pub[:32])
      fmt.Printf("    Y %064x\n", pub[32:])
      fmt.Printf("    key 0x40 bytes  blob 0x80 bytes  round-trip OK\n")
   }

   if len(pubs) != 15 {
      return moFail("only %d distinct public keys, expected 15", len(pubs))
   }

   fmt.Printf("\ngenerated %d/15 key+licence pairs in %s\n", len(pubs), out)
   fmt.Printf("key_NN.pub is deterministic; lic_NN.blob is not (random ephemeral scalar).\n")
   return 0
}

// oracle.go end
