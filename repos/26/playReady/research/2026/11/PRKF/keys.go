// keys.go begin
//go:build windows

// cmdKeys is the second half of prkf -1.
//
// Extracts the signing and encryption key components from a PRKF container.
//
// The names are fixed below. It reads msprcore.bla from the working
// directory, finds the 0x1009 key-material section, parses every 0x100f
// record inside it, and writes four components into testdata/:
//
//   testdata/extracted.sig.pub   signing public key
//   testdata/extracted.sig.prv   signing private component (32 bytes, still obfuscated)
//   testdata/extracted.enc.pub   encryption public key
//   testdata/extracted.enc.prv   encryption private component (65 bytes)
//
// The signing record is the one immediately preceding the unique 65-byte
// encryption record; see the comment at that site for why no header field can
// discriminate.
//
// The structural parse is the only check. No sample key files are consulted:
// the record layout and the uniqueness of the 65-byte private component are
// what identify the two keys.
//
// NOTE: this file has no entry point of its own. main.go's cmdExtract calls
// cmdCert and then this, so the two halves of -1 cannot be run separately and
// cannot disagree about whether the chain was carved. The input path is
// corePath, declared in main.go: one constant for the one file both halves
// read.
package main

import (
   "bytes"
   "encoding/binary"
   "encoding/hex"
   "fmt"
   "os"
)

const keysOut = "extracted" // output stem, inside outDir

func cmdKeys() error {
   outNames := []string{"sig.pub", "sig.prv", "enc.pub", "enc.prv"}

   b, err := os.ReadFile(corePath)
   if err != nil || len(b) < 4 || string(b[:4]) != "PRKF" {
      return fmt.Errorf("%s: not a PRKF", corePath)
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
      return fmt.Errorf("no 0x1009 key-material section")
   }

   var recs []*keyRecord
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
   var encC []*keyRecord
   for _, r := range recs {
      if r.privlen == 65 {
         encC = append(encC, r)
      }
   }
   if len(encC) != 1 {
      return fmt.Errorf("%d records have a 65-byte private component (need 1)", len(encC))
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
      return fmt.Errorf("internal error: encryption record not found")
   }
   if i == 0 {
      return fmt.Errorf("encryption key is the first record - nothing precedes it")
   }

   sig := recs[i-1]
   if sig.privlen != 32 {
      return fmt.Errorf("record before the encryption key has a %d-byte private component, expected 32", sig.privlen)
   }
   fmt.Printf("signing key: %#x  (record preceding the encryption key)\n", sig.off)

   if bytes.Equal(sig.pub, enc.pub) {
      return fmt.Errorf("signing and encryption records are not distinct")
   }

   data := map[string][]byte{
      "sig.pub": sig.pub,
      "sig.prv": sig.priv,
      "enc.pub": enc.pub,
      "enc.prv": enc.priv,
   }

   fmt.Println("\nwritten:")
   for _, k := range outNames {
      p := outFile(keysOut + "." + k)
      v := data[k]
      if err := os.WriteFile(p, v, 0666); err != nil {
         return fmt.Errorf("write %s: %v", p, err)
      }
      fmt.Printf("  %s  %2d B\n", p, len(v))
   }

   return nil
}

func pubHex(pub []byte) string {
   n := len(pub)
   if n > 8 {
      n = 8
   }
   return hex.EncodeToString(pub[:n])
}

type keyRecord struct {
   off     int
   publen  int
   pub     []byte
   privlen int
   priv    []byte
}

func parseRec(buf []byte, ps, pe int) *keyRecord {
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
   return &keyRecord{
      off: ps, publen: publen, pub: pub,
      privlen: privlen, priv: priv,
   }
}

// section is a parsed PRKF section header. Only the type and the payload span
// are retained: the tag, offset and total size are used while walking and
// have no consumer afterwards.
type section struct {
   typ, ps, pe int
}

func walk(buf []byte, start, end int) []section {
   var out []section
   off := start
   for off+8 <= end {
      typ := int(binary.BigEndian.Uint16(buf[off+2:]))
      total := int(binary.BigEndian.Uint32(buf[off+4:]))
      if total < 8 || off+total > end {
         break
      }
      out = append(out, section{typ: typ, ps: off + 8, pe: off + total})
      off += total
   }
   return out
}

// keys.go end
