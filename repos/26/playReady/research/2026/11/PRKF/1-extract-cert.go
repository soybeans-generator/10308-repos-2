// 1-extract-cert.go begin

// Carves the CHAI certificate chain out of msprcore.bla.
//
// It scans for CHAI headers, keeps only chains that parse self-consistently
// (the certificate entries must tile the chain exactly), prefers a chain
// whose preceding u32 big-endian length prefix equals its total length, and
// writes the carved bytes to extracted.cert.
//
// fake.cert is optional: when present, the carve is cross-checked against it
// and any mismatch aborts before anything is written. When absent, the carve
// is written unconditionally, because the structural parse is already a
// strong check on its own.
//
// No arguments. All names are fixed below.
package main

import (
   "bytes"
   "encoding/binary"
   "fmt"
   "os"
)

const (
   corePath = "msprcore.bla"
   refPath  = "fake.cert" // optional: verification only
   outPath  = "extracted.cert"

   chaiHdr = 20 // magic(4) version(4) total_length(4) flags(4) cert_count(4)
   certHdr = 16 // magic(4) version(4) total_length(4) certificate_length(4)
)

var (
   magicCHAI = []byte("CHAI")
   magicCERT = []byte("CERT")
)

func die(v ...any) {
   fmt.Fprintln(os.Stderr, v...)
   os.Exit(1)
}

func hexSpace(b []byte) string {
   var sb bytes.Buffer
   for i, v := range b {
      if i > 0 {
         sb.WriteByte(' ')
      }
      fmt.Fprintf(&sb, "%02x", v)
   }
   return sb.String()
}

func main() {
   if fi, err := os.Stat(corePath); err != nil || !fi.Mode().IsRegular() {
      die("missing input: " + corePath)
   }
   buf, err := os.ReadFile(corePath)
   if err != nil {
      die(err)
   }
   fmt.Printf("%s : %d bytes\n", corePath, len(buf))

   var reference []byte
   haveRef := false
   if fi, err := os.Stat(refPath); err == nil && fi.Mode().IsRegular() {
      reference, err = os.ReadFile(refPath)
      if err != nil {
         die(err)
      }
      haveRef = true
      fmt.Printf("%s : %d bytes\n", refPath, len(reference))
   } else {
      fmt.Printf("%s : absent -> skipping verification (carve is self-validating)\n", refPath)
   }

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
      die("no valid CHAI chain found")
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
   var confirmed []*chain
   for _, c := range candidates {
      if c.prefixOK {
         confirmed = append(confirmed, c)
      }
   }
   ch := candidates[0]
   if len(confirmed) > 0 {
      ch = confirmed[0]
   }
   if len(candidates) > 1 {
      how := "first valid, unconfirmed"
      if len(confirmed) > 0 {
         how = "length prefix"
      }
      fmt.Printf("\nselected 0x%x (%s)\n", ch.base, how)
   }

   base, totalLength := ch.base, ch.totalLength
   blob := buf[base : base+int(totalLength)]

   // ---- context around the chain -----------------------------------
   lo := base - 16
   if lo < 0 {
      lo = 0
   }
   fmt.Printf("\nbytes 0x%x..0x%x (before CHAI):\n", lo, base)
   fmt.Println("  " + hexSpace(buf[lo:base]))
   switch {
   case !ch.hasPrefix:
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

   // ---- optional cross-check against fake.cert ----------------------
   verdict := ""
   switch {
   case !haveRef:
      fmt.Println("\nno reference file - writing carved chain unconditionally")
      verdict = "unverified"

   case bytes.Equal(reference, blob):
      fmt.Println("\nEXTRACTION OK - carved chain is byte-identical to fake.cert")
      verdict = "exact"

   case len(reference) == len(blob)+1 && bytes.Equal(reference[1:], blob):
      lead := reference[0]
      prev := -1 // -1 means "no byte available"
      if base >= 1 {
         prev = int(buf[base-1])
      }
      fmt.Printf("\nfake.cert = leading byte 0x%02x + chain (chain matches exactly)\n", lead)
      if prev >= 0 && lead == byte(prev) {
         fmt.Printf("leading byte == %s[0x%x] (0x%02x)\n", corePath, base-1, prev)
         fmt.Println("-> fake.cert is a verbatim span of the core starting one byte before CHAI")
         verdict = "leading-byte"
      } else {
         idx := base - 1
         if idx < 0 {
            idx = 0
         }
         if prev >= 0 {
            fmt.Printf("but %s[0x%x] = %d - leading byte unexplained\n", corePath, idx, prev)
         } else {
            fmt.Printf("but %s[0x%x] = n/a - leading byte unexplained\n", corePath, idx)
         }
         verdict = "mismatch"
      }

   default:
      fmt.Println("\nMISMATCH - neither exact nor 1-leading-byte match")
      n := len(blob)
      if len(reference) < n {
         n = len(reference)
      }
      diff := -1
      for j := 0; j < n; j++ {
         if blob[j] != reference[j] {
            diff = j
            break
         }
      }
      if diff >= 0 {
         fmt.Printf("  first difference at offset 0x%x\n", diff)
         fmt.Printf("    carved: %s\n", hexSpace(blob[max(diff-8, 0):min(diff+8, len(blob))]))
         fmt.Printf("    ref   : %s\n", hexSpace(reference[max(diff-8, 0):min(diff+8, len(reference))]))
      } else {
         fmt.Printf("  common prefix identical over %d bytes (lengths differ: %d vs %d)\n",
            n, len(blob), len(reference))
      }
      verdict = "mismatch"
   }

   if verdict == "mismatch" {
      die("not writing output - investigate the mismatch first")
   }

   if err := os.WriteFile(outPath, blob, 0o644); err != nil {
      die(err)
   }
   fmt.Printf("\nwrote %s (%d bytes, verdict: %s)\n", outPath, len(blob), verdict)
}

// u32be reads a big-endian uint32 at off, reporting whether it fit.
func u32be(buf []byte, off int) (uint32, bool) {
   if off < 0 || off+4 > len(buf) {
      return 0, false
   }
   return binary.BigEndian.Uint32(buf[off:]), true
}

type certEntry struct {
   off    int
   total  uint32
   length uint32
}

type chain struct {
   base        int
   version     uint32
   totalLength uint32
   flags       uint32
   certCount   uint32
   certs       []certEntry
   warnings    []string
   prefix      uint32
   hasPrefix   bool
   prefixOK    bool
}

// parseChain is a self-validating parse of a CHAI chain at base.
func parseChain(buf []byte, base int) (*chain, bool) {
   if base < 0 || base+4 > len(buf) || !bytes.Equal(buf[base:base+4], magicCHAI) {
      return nil, false
   }

   version, ok1 := u32be(buf, base+4)
   totalLength, ok2 := u32be(buf, base+8)
   flags, ok3 := u32be(buf, base+12)
   certCount, ok4 := u32be(buf, base+16)
   if !ok1 || !ok2 || !ok3 || !ok4 {
      return nil, false
   }
   if totalLength < chaiHdr || int(totalLength) > len(buf)-base {
      return nil, false
   }

   c := &chain{
      base:        base,
      version:     version,
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
      _, okA := u32be(buf, off+4) // certificate version (unused)
      cTot, okB := u32be(buf, off+8)
      cLen, okC := u32be(buf, off+12)
      if !okA || !okB || !okC {
         return nil, false
      }
      if cTot < certHdr || off+int(cTot) > end {
         return nil, false
      }
      if cLen != cTot-certHdr {
         c.warnings = append(c.warnings, fmt.Sprintf(
            "cert %d @ 0x%x: certificate_length %d != entry %d - %d",
            n, off, cLen, cTot, certHdr))
      }
      c.certs = append(c.certs, certEntry{off: off, total: cTot, length: cLen})
      off += int(cTot)
   }
   if off != end { // entries must tile the chain exactly
      return nil, false
   }

   if base >= 4 {
      if p, ok := u32be(buf, base-4); ok {
         c.prefix = p
         c.hasPrefix = true
         c.prefixOK = p == totalLength
      }
   }

   return c, true
}

// 1-extract-cert.go end
