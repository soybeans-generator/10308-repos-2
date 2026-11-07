// extract.go begin
//go:build windows

// prkf -1, in two halves that cannot be run separately.
//
//   cmdCert   carves the CHAI certificate chain out of corePath
//   cmdKeys   parses the PRKF key-material section and writes the components
//
// main.go's cmdExtract calls cmdCert and then cmdKeys, so a failure in either
// half aborts the step: a run that produced a chain but no keys is not a state
// any later step can use. The two halves read the same file and write disjoint
// outputs, which is why they share one input path and one file.
//
// Every path used here is declared in main.go's manifest: corePath for the
// input, certPath for the chain, and sigPubPath/sigPrvPath/encPubPath/encPrvPath
// for the four key components.
//
// # THE CHAIN
//
// It scans for CHAI headers, keeps only chains that parse self-consistently
// (the certificate entries must tile the chain exactly), prefers a chain whose
// preceding u32 big-endian length prefix equals its total length, and writes
// the carved bytes to certPath.
//
// # THE KEYS
//
// It finds the 0x1009 key-material section, parses every 0x100f record inside
// it, and writes four components:
//
//   sigPubPath   signing public key
//   sigPrvPath   signing private component (32 bytes, still obfuscated)
//   encPubPath   encryption public key
//   encPrvPath   encryption private component (65 bytes)
//
// The signing record is the one immediately preceding the unique 65-byte
// encryption record; see the comment at that site for why no header field can
// discriminate.
//
// The structural parse is the only check in either half. No sample key files
// are consulted: internal consistency identifies the chain, and the record
// layout plus the uniqueness of the 65-byte private component identify the two
// keys.
package main

import (
   "bytes"
   "encoding/binary"
   "encoding/hex"
   "errors"
   "fmt"
   "os"
)

const (
   chaiHdr = 20 // magic(4) version(4) total_length(4) flags(4) cert_count(4)
   certHdr = 16 // magic(4) version(4) total_length(4) certificate_length(4)
)

var (
   magicCHAI = []byte("CHAI")
   magicCERT = []byte("CERT")
)

// ------------------------------------------------- first half: the CHAI chain

// cmdCert carves the CHAI certificate chain out of corePath and writes it to
// certPath. Selection is structural: a candidate must tile its own certificate
// entries exactly, and a chain whose preceding length prefix matches its total
// length is preferred over one whose does not.
func cmdCert() error {
   if fi, err := os.Stat(corePath); err != nil || !fi.Mode().IsRegular() {
      return fmt.Errorf("missing input: %s\n  put the PlayReady sample there before running", corePath)
   }
   buf, err := os.ReadFile(corePath)
   if err != nil {
      return err
   }
   fmt.Printf("%s : %d bytes\n", corePath, len(buf))

   // ---- collect every structurally valid candidate -----------------
   var candidates []*chain
   for i := 0; ; {
      j := bytes.Index(buf[i:], magicCHAI)
      if j < 0 {
         break
      }
      i += j
      if c, ok := parseChain(buf, i); ok {
         candidates = append(candidates, c)
      }
      i++
   }

   if len(candidates) == 0 {
      return errors.New("no valid CHAI chain found")
   }

   fmt.Printf("\n%d valid CHAI candidate(s):\n", len(candidates))
   for _, c := range candidates {
      tag := "no length prefix"
      if c.prefixOK {
         tag = "length-prefix confirmed"
      }
      fmt.Printf("  @ 0x%x  %d bytes  %d certs  flags=0x%x  [%s]\n",
         c.base, c.totalLength, c.certCount, c.flags, tag)
   }

   // prefer the length-prefix-confirmed chain; fall back to first valid
   ch := candidates[0]
   for _, c := range candidates {
      if c.prefixOK {
         ch = c
         break
      }
   }
   if len(candidates) > 1 {
      how := "first valid, unconfirmed"
      if ch.prefixOK {
         how = "length prefix"
      }
      fmt.Printf("\nselected 0x%x (%s)\n", ch.base, how)
   }

   base, totalLength := ch.base, ch.totalLength
   blob := buf[base : base+int(totalLength)]

   // ---- context around the chain -----------------------------------
   lo := max(base-16, 0)
   fmt.Printf("\nbytes 0x%x..0x%x (before CHAI):\n", lo, base)
   fmt.Printf("  % x\n", buf[lo:base])
   switch {
   case base < 4:
      fmt.Println("  (chain starts before offset 4 - no length prefix possible)")
   case ch.prefixOK:
      fmt.Printf("u32be at CHAI-4 = 0x%08x == chain length -> PRKF length-prefix confirmed\n", ch.prefix)
   default:
      fmt.Printf("u32be at CHAI-4 = 0x%08x != chain length (%d) -> not a PRKF-length-prefixed span\n",
         ch.prefix, totalLength)
   }

   for _, w := range ch.warnings {
      fmt.Printf("warning: %s\n", w)
   }

   // ---- write ------------------------------------------------------
   if err := os.WriteFile(certPath, blob, 0o644); err != nil {
      return err
   }
   fmt.Printf("\nwrote %s (%d bytes)\n", certPath, len(blob))
   return nil
}

// ---------------------------------------------- second half: the key records

// cmdKeys parses the PRKF key-material section and writes the four key
// components. It re-reads corePath rather than taking buf from cmdCert: the
// two halves are independent, and neither holds state for the other.
func cmdKeys() error {
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
      head := r.pub
      if len(head) > 8 {
         head = head[:8]
      }
      fmt.Printf("  %#8x  pub=%2dB priv=%2dB %s\n",
         r.off, len(r.pub), len(r.priv), hex.EncodeToString(head))
   }

   // --- encryption key: the unique 65-byte private component
   var encC []*keyRecord
   for _, r := range recs {
      if len(r.priv) == 65 {
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
   if len(sig.priv) != 32 {
      return fmt.Errorf("record before the encryption key has a %d-byte private component, expected 32", len(sig.priv))
   }
   fmt.Printf("signing key: %#x  (record preceding the encryption key)\n", sig.off)

   if bytes.Equal(sig.pub, enc.pub) {
      return fmt.Errorf("signing and encryption records are not distinct")
   }

   fmt.Println("\nwritten:")
   for _, o := range []struct {
      path string
      b    []byte
   }{
      {sigPubPath, sig.pub},
      {sigPrvPath, sig.priv},
      {encPubPath, enc.pub},
      {encPrvPath, enc.priv},
   } {
      if err := os.WriteFile(o.path, o.b, 0666); err != nil {
         return fmt.Errorf("write %s: %v", o.path, err)
      }
      fmt.Printf("  %s  %2d B\n", o.path, len(o.b))
   }

   return nil
}

// u32be reads a big-endian uint32 at off, reporting whether it fit.
func u32be(buf []byte, off int) (uint32, bool) {
   if off < 0 || off+4 > len(buf) {
      return 0, false
   }
   return binary.BigEndian.Uint32(buf[off:]), true
}

type chain struct {
   base        int
   totalLength uint32
   flags       uint32
   certCount   uint32
   warnings    []string
   prefix      uint32
   prefixOK    bool
}

// parseChain is a self-validating parse of a CHAI chain at base.
//
// Only the header fields that are actually used are decoded: the certificate
// version is not needed to locate anything, and the per-certificate lengths
// are consumed in the loop rather than retained.
func parseChain(buf []byte, base int) (*chain, bool) {
   if base < 0 || base+4 > len(buf) || !bytes.Equal(buf[base:base+4], magicCHAI) {
      return nil, false
   }

   totalLength, okTL := u32be(buf, base+8)
   flags, okFl := u32be(buf, base+12)
   certCount, okCC := u32be(buf, base+16)
   if !okTL || !okFl || !okCC {
      return nil, false
   }
   if totalLength < chaiHdr || int(totalLength) > len(buf)-base {
      return nil, false
   }

   c := &chain{
      base:        base,
      totalLength: totalLength,
      flags:       flags,
      certCount:   certCount,
   }

   end := base + int(totalLength)
   off := base + chaiHdr

   for n := uint32(0); n < certCount; n++ {
      if off+certHdr > end || !bytes.Equal(buf[off:off+4], magicCERT) {
         return nil, false
      }

      // No bounds check needed on these reads: off+certHdr <= end <= len(buf)
      // was just established, so both fields lie inside the chain.
      cTot := binary.BigEndian.Uint32(buf[off+8:])
      cLen := binary.BigEndian.Uint32(buf[off+12:])

      if cTot < certHdr || off+int(cTot) > end {
         return nil, false
      }

      // An entry is header + certificate body + trailer, and the trailer is
      // not zero: every entry in a real chain carries a fixed-size signature
      // block after the certificate (144 bytes in msprcore.bla, 288 for the
      // leaf, which carries two). So certificate_length is expected to be
      // smaller than the entry - requiring equality would warn on every
      // valid chain. The only real defect is a body that does not fit.
      if cLen > cTot-certHdr {
         c.warnings = append(c.warnings, fmt.Sprintf(
            "cert %d @ 0x%x: certificate_length %d exceeds the entry body (%d)",
            n, off, cLen, cTot-certHdr))
      }

      off += int(cTot)
   }
   if off != end { // entries must tile the chain exactly
      return nil, false
   }

   // The length prefix lives in the four bytes before the magic. u32be rejects
   // off < 0, so a chain near the start of the file simply has none.
   if p, ok := u32be(buf, base-4); ok {
      c.prefix = p
      c.prefixOK = p == totalLength
   }

   return c, true
}

// keyRecord is one 0x100f record's public and private components. The lengths
// are len(pub) and len(priv): the record carries them as u32 fields, but every
// consumer wants the slice, and a separate field could disagree with it.
type keyRecord struct {
   off  int
   pub  []byte
   priv []byte
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
   return &keyRecord{off: ps, pub: pub, priv: priv}
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

// extract.go end
