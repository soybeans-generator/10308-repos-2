// bla.go begin
// -5: carve the CHAI certificate chain out of the sample and write the four key components.
//
// NOTHING HERE READS THE DLL. A candidate chain must tile its own certificate entries
// exactly; a chain whose preceding length prefix matches its total length is preferred.
package main

import (
   "bytes"
   "encoding/binary"
   "errors"
   "fmt"
   "os"
)

// certHdr is the fixed part of one certificate entry:
// magic(4) version(4) total_length(4) certificate_length(4).
const certHdr = 16

// cmdCert carves the CHAI certificate chain out of corePath.
func cmdCert() error {
   if !isFile(corePath) {
      return fmt.Errorf("missing input: %s\n  put the PlayReady sample there before running", corePath)
   }
   buf, err := os.ReadFile(corePath)
   if err != nil {
      return err
   }
   fmt.Printf("%s : %d bytes\n", corePath, len(buf))

   magic := []byte("CHAI")
   var candidates []*chain
   for i := 0; ; i++ {
      j := bytes.Index(buf[i:], magic)
      if j < 0 {
         break
      }
      i += j
      if c, ok := parseChain(buf, i); ok {
         candidates = append(candidates, c)
      }
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

   switch {
   case ch.base < 4:
      fmt.Println("prefix: none (chain starts before offset 4)")
   case ch.prefixOK:
      fmt.Printf("prefix: u32be at CHAI-4 = %d == chain length\n", ch.prefix)
   default:
      fmt.Printf("prefix: u32be at CHAI-4 = %d != chain length %d\n", ch.prefix, ch.totalLength)
   }

   blob := buf[ch.base : ch.base+int(ch.totalLength)]
   if err := os.WriteFile(certPath, blob, 0o644); err != nil {
      return err
   }
   fmt.Printf("\nwrote %s (%d bytes)\n", certPath, len(blob))
   return nil
}

// cmdExtract is -5: carve the chain, then extract the keys. Idempotent, because -7 calls it
// when the enc pair is absent.
func cmdExtract() error {
   if err := cmdCert(); err != nil {
      return err
   }
   fmt.Println()
   return cmdKeys()
}

// cmdKeys parses the PRKF key-material section and writes the four key components.
func cmdKeys() error {
   b, err := os.ReadFile(corePath)
   if err != nil || len(b) < 4 || string(b[:4]) != "PRKF" {
      return fmt.Errorf("%s: not a PRKF", corePath)
   }

   var km section
   found := false
   for _, s := range walk(b, 12, len(b)) {
      if s.typ == 0x1009 {
         km, found = s, true
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
         r.off, len(r.pub), len(r.priv), hexOf(head))
   }

   // The encryption key is the unique record with a 65-byte private component; the signing
   // key is the record immediately before it. No field separates it from the other 32-byte
   // record: ver/flags/z1/z2 are identical across all three and every pubkey occurs twice.
   var enc *keyRecord
   encIdx := -1
   for j, r := range recs {
      if len(r.priv) == 65 {
         if enc != nil {
            return fmt.Errorf("more than one record has a 65-byte private component")
         }
         enc, encIdx = r, j
      }
   }
   if enc == nil {
      return fmt.Errorf("no record has a 65-byte private component")
   }
   fmt.Printf("encryption key: %#x  (65-byte private component)\n", enc.off)

   if encIdx == 0 {
      return fmt.Errorf("no 32-byte record precedes the encryption key")
   }
   sig := recs[encIdx-1]
   if len(sig.priv) != 32 {
      return fmt.Errorf("record before the encryption key has a %d-byte private component, expected 32",
         len(sig.priv))
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
      if err := os.WriteFile(o.path, o.b, 0o644); err != nil {
         return fmt.Errorf("write %s: %v", o.path, err)
      }
      fmt.Printf("  %s  %2d B\n", o.path, len(o.b))
   }
   return nil
}

type chain struct {
   base        int
   totalLength uint32
   flags       uint32
   certCount   uint32
   prefix      uint32
   prefixOK    bool
}

// parseChain is a self-validating parse of a CHAI chain at base.
func parseChain(buf []byte, base int) (*chain, bool) {
   const chaiHdr = 20 // magic(4) version(4) total_length(4) flags(4) cert_count(4)

   if base < 0 || base+chaiHdr > len(buf) || !bytes.Equal(buf[base:base+4], []byte("CHAI")) {
      return nil, false
   }

   totalLength := binary.BigEndian.Uint32(buf[base+8:])
   flags := binary.BigEndian.Uint32(buf[base+12:])
   certCount := binary.BigEndian.Uint32(buf[base+16:])
   if totalLength < chaiHdr || int(totalLength) > len(buf)-base {
      return nil, false
   }

   c := &chain{base: base, totalLength: totalLength, flags: flags, certCount: certCount}
   end := base + int(totalLength)
   off := base + chaiHdr

   for n := uint32(0); n < certCount; n++ {
      if off+certHdr > end || !bytes.Equal(buf[off:off+4], []byte("CERT")) {
         return nil, false
      }
      cTot := binary.BigEndian.Uint32(buf[off+8:])
      if cTot < certHdr || off+int(cTot) > end {
         return nil, false
      }
      off += int(cTot)
   }
   if off != end { // entries must tile the chain exactly
      return nil, false
   }

   if base >= 4 {
      c.prefix = binary.BigEndian.Uint32(buf[base-4:])
      c.prefixOK = c.prefix == totalLength
   }
   return c, true
}

// keyRecord is one 0x100f record's public and private components.
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
   return &keyRecord{off: ps, pub: pub, priv: buf[q+12 : q+12+privlen]}
}

// section is a parsed PRKF section header.
type section struct {
   typ, ps, pe int
}

func walk(buf []byte, start, end int) []section {
   var out []section
   for off := start; off+8 <= end; {
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

// bla.go end
