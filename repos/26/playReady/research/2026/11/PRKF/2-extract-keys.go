// 2-extract-keys.go begin

// Extracts the signing and encryption key components from a PRKF container.
//
// Three optional arguments, in order: the PRKF path (default msprcore.bla),
// the reference stem (default fake) and the output stem (default extracted).
// It finds the 0x1009 key-material section, parses every 0x100f record inside
// it, and writes four components:
//
//   <outstem>.sig.pub   signing public key
//   <outstem>.sig.prv   signing private component (32 bytes, still obfuscated)
//   <outstem>.enc.pub   encryption public key
//   <outstem>.enc.prv   encryption private component (65 bytes)
//
// The signing record is the one immediately preceding the unique 65-byte
// encryption record; see the comment at that site for why no header field can
// discriminate. <refstem>.sig.* (default fake.sig.*) is compared when present:
// absence is not an error, a mismatch is.
package main

import (
   "bytes"
   "encoding/binary"
   "encoding/hex"
   "fmt"
   "os"
   "path/filepath"
)

func abs(p string) string {
   a, err := filepath.Abs(p)
   if err != nil {
      return p
   }
   return a
}

func main() {
   src, refstem, outstem := "msprcore.bla", "fake", "extracted"

   args := os.Args[1:]
   if len(args) > 0 {
      src = args[0]
   }
   if len(args) > 1 {
      refstem = args[1]
   }
   if len(args) > 2 {
      outstem = args[2]
   }

   code, err := run(src, refstem, outstem)
   if err != nil {
      fmt.Fprintln(os.Stderr, err)
      os.Exit(1)
   }
   os.Exit(code)
}

func pubHex(pub []byte) string {
   n := len(pub)
   if n > 8 {
      n = 8
   }
   return hex.EncodeToString(pub[:n])
}

func run(src, refstem, outstem string) (int, error) {
   outNames := []string{"sig.pub", "sig.prv", "enc.pub", "enc.prv"}
   outs := make(map[string]string, len(outNames))
   for _, k := range outNames {
      outs[k] = outstem + "." + k
   }

   refNames := []string{"sig.pub", "sig.prv"}
   refs := make(map[string]string, len(refNames))
   for _, k := range refNames {
      refs[k] = refstem + "." + k
   }

   fail := func(format string, args ...any) (int, error) {
      return 1, fmt.Errorf(format, args...)
   }

   absSrc := abs(src)
   absRefs := make(map[string]bool, len(refNames))
   for _, k := range refNames {
      absRefs[abs(refs[k])] = true
   }
   for _, k := range outNames {
      ao := abs(outs[k])
      if ao == absSrc || absRefs[ao] {
         return fail("refusing to overwrite %s - pick another outstem", outs[k])
      }
   }

   b, err := os.ReadFile(src)
   if err != nil || len(b) < 4 || string(b[:4]) != "PRKF" {
      return fail("%s: not a PRKF", src)
   }

   var km section
   found := false
   for _, s := range walk(b, 12, len(b)) {
      if s.typ == 0x1009 {
         km = s
         found = true
         break
      }
   }
   if !found {
      return fail("no 0x1009 key-material section")
   }

   var recs []*record
   for _, s := range walk(b, km.ps, km.pe) {
      if s.typ == 0x100f {
         if r := parseRec(b, s.ps, s.pe); r != nil {
            recs = append(recs, r)
         }
      }
   }

   fmt.Printf("usable records: %d\n", len(recs))
   for _, r := range recs {
      fmt.Printf("  %#8x  pub=%2dB priv=%2dB %s\n",
         r.off, r.publen, r.privlen, pubHex(r.pub))
   }

   // --- encryption key: the unique 65-byte private component
   var encC []*record
   for _, r := range recs {
      if r.privlen == 65 {
         encC = append(encC, r)
      }
   }
   if len(encC) != 1 {
      return fail("%d records have a 65-byte private component (need 1)", len(encC))
   }
   enc := encC[0]
   fmt.Printf("encryption key: %#x  (65-byte private component)\n", enc.off)

   // --- signing key: the 32-byte record immediately preceding the encryption
   //     key.  No field in the PRKF separates it from the other 32-byte record:
   //     ver/flags/z1/z2 are identical across all three (0x0001 / 0x0100 / 0 / 0)
   //     and every pubkey occurs exactly twice, so neither header values nor
   //     cross-reference counts discriminate.
   i := -1
   for j, r := range recs {
      if r == enc {
         i = j
         break
      }
   }
   if i < 0 {
      return fail("internal error: encryption record not found")
   }
   if i == 0 {
      return fail("encryption key is the first record - nothing precedes it")
   }

   sig := recs[i-1]
   if sig.privlen != 32 {
      return fail("record before the encryption key has a %d-byte private component, expected 32", sig.privlen)
   }
   fmt.Printf("signing key: %#x  (record preceding the encryption key)\n", sig.off)

   if sig.off == enc.off || bytes.Equal(sig.pub, enc.pub) {
      return fail("signing and encryption records are not distinct")
   }

   data := map[string][]byte{
      "sig.pub": sig.pub,
      "sig.prv": sig.priv,
      "enc.pub": enc.pub,
      "enc.prv": enc.priv,
   }

   fmt.Println("\nwritten:")
   for _, k := range outNames {
      v := data[k]
      if err := os.WriteFile(outs[k], v, 0666); err != nil {
         return fail("write %s: %v", outs[k], err)
      }
      fmt.Printf("  %s  %2d B\n", outs[k], len(v))
   }

   // --- optional verification: only if the reference files happen to exist.
   //     Their absence is not an error; a mismatch is.
   ok := true
   fmt.Printf("\nverified against %s.sig.* :\n", refstem)
   for _, k := range refNames {
      ref, err := os.ReadFile(refs[k])
      if err != nil {
         fmt.Printf("  [ n/a] %s not present\n", refs[k])
         continue
      }

      same := bytes.Equal(data[k], ref)
      ok = ok && same

      if same {
         fmt.Printf("  [ OK ] %s == %s\n", outs[k], refs[k])
      } else {
         fmt.Printf("  [FAIL] %s != %s\n", outs[k], refs[k])
      }
   }

   if ok {
      fmt.Println("\nPASS")
      return 0, nil
   }
   fmt.Println("\nFAIL")
   return 1, nil
}

type record struct {
   off     int
   publen  int
   pub     []byte
   privlen int
   priv    []byte
}

func parseRec(buf []byte, ps, pe int) *record {
   if ps+8 > pe {
      return nil
   }

   // >HHI : ver(H) flags(H) publen(I)
   publen := int(binary.BigEndian.Uint32(buf[ps+4:]))
   if publen > 0x100 || ps+8+publen+12 > pe {
      return nil
   }

   pub := buf[ps+8 : ps+8+publen]
   q := ps + 8 + publen

   // >III : z1 z2 privlen
   privlen := int(binary.BigEndian.Uint32(buf[q+8:]))
   if privlen > 0x200 || q+12+privlen+20 > pe {
      return nil
   }

   priv := buf[q+12 : q+12+privlen]
   return &record{
      off: ps, publen: publen, pub: pub,
      privlen: privlen, priv: priv,
   }
}

type section struct {
   off, tag, typ, total int
   ps, pe               int
}

func walk(buf []byte, start, end int) []section {
   var out []section
   off := start
   for off+8 <= end {
      tag := int(binary.BigEndian.Uint16(buf[off:]))
      typ := int(binary.BigEndian.Uint16(buf[off+2:]))
      total := int(binary.BigEndian.Uint32(buf[off+4:]))
      if total < 8 || off+total > end {
         break
      }
      out = append(out, section{
         off: off, tag: tag, typ: typ, total: total,
         ps: off + 8, pe: off + total,
      })
      off += total
   }
   return out
}

// 2-extract-keys.go end
