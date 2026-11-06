// 1-extract-cert.go begin
//go:build windows

// prkf is the PlayReady key-extraction pipeline: four steps, one binary, one
// package, one folder. Each step is selected by a flag and keeps its
// implementation in the file it was always in:
//
//   prkf -1    1-extract-cert.go   carve the CHAI certificate chain
//   prkf -2    2-extract-keys.go   extract the sig/enc key components
//   prkf -3    3-find-sub.go       locate the signing-key routine descriptor
//   prkf -4    4-decrypt.go        decrypt the signing key
//
// Run the steps in order, in one directory: -3 writes prsubs.json, -4 reads
// it, and -4 consumes what -2 wrote. Every file the pipeline creates lands in
// testdata/, so a run is disposable and the working directory stays clean.
//
// There is one hidden mode: `prkf -one <descVA>`, which -3 spawns for each
// candidate descriptor. It lives on its own FlagSet so it never appears in
// `prkf -h`. See 3-find-sub.go for why it is a separate process at all.
//
// The four files share one namespace, so a handful of identifiers had to be
// renamed: see the note at the top of each file.
package main

import (
   "bytes"
   "encoding/binary"
   "errors"
   "flag"
   "fmt"
   "os"
   "path/filepath"
   "strconv"
   "strings"
)

// ------------------------------------------------------- step 1: the chain

const (
   corePath = "msprcore.bla" // input, working directory
   certOut  = "extracted.cert"

   chaiHdr = 20 // magic(4) version(4) total_length(4) flags(4) cert_count(4)
   certHdr = 16 // magic(4) version(4) total_length(4) certificate_length(4)
)

// ------------------------------------------------------------------ driver

// outDir is where every file this program creates is written. Inputs are
// still read from the working directory (msprcore.bla, fake.sig.*); only
// outputs are redirected here.
//
// Nothing else in the pipeline should spell a directory: write through
// outFile so the whole run can be thrown away with `rm -rf testdata`.
const outDir = "testdata"

var (
   magicCHAI = []byte("CHAI")
   magicCERT = []byte("CERT")
)

// cmdCert implements prkf -1.
//
// Carves the CHAI certificate chain out of msprcore.bla.
//
// It scans for CHAI headers, keeps only chains that parse self-consistently
// (the certificate entries must tile the chain exactly), prefers a chain
// whose preceding u32 big-endian length prefix equals its total length, and
// writes the carved bytes to testdata/extracted.cert.
//
// The structural parse is the only check. A candidate must be internally
// consistent to be considered at all, and no reference file is consulted.
//
// Takes no arguments. All names are fixed below.
func cmdCert(args []string) error {
   if len(args) != 0 {
      return fmt.Errorf("prkf -1 takes no arguments, got %q", args[0])
   }

   if fi, err := os.Stat(corePath); err != nil || !fi.Mode().IsRegular() {
      return errors.New("missing input: " + corePath)
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

   // ---- write ------------------------------------------------------
   out := outFile(certOut)
   if err := os.WriteFile(out, blob, 0o644); err != nil {
      return err
   }
   fmt.Printf("\nwrote %s (%d bytes)\n", out, len(blob))
   return nil
}

// ensureOutDir creates outDir if it does not exist. Called once from main
// before dispatch, so no step has to care.
func ensureOutDir() error {
   return os.MkdirAll(outDir, 0o755)
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

// isWorkerInvocation reports whether argv asks for the internal worker mode
// (`prkf -one <descVA>`). Only -3 produces this, and only through
// exec.Command, so the check is deliberately narrow: it matches -one and
// --one, with or without =value, and nothing else.
func isWorkerInvocation(argv []string) bool {
   if len(argv) == 0 {
      return false
   }
   a := argv[0]
   return a == "-one" || a == "--one" ||
      strings.HasPrefix(a, "-one=") || strings.HasPrefix(a, "--one=")
}

func main() {
   // The single-descriptor worker is checked before the main FlagSet exists,
   // so it stays out of `prkf -h`. It is spawned by -3, never by hand.
   if isWorkerInvocation(os.Args[1:]) {
      workerMain(os.Args[1:])
      return
   }

   step1 := flag.Bool("1", false,
      "carve the CHAI certificate chain ("+outFile("extracted.cert")+")")
   step2 := flag.Bool("2", false,
      "extract the key components ("+outFile("extracted")+".{sig,enc}.{pub,prv})")
   step3 := flag.Bool("3", false,
      "locate the signing-key routine ("+outFile("prsubs.json")+", "+outFile("findprsub.txt")+")")
   step4 := flag.Bool("4", false,
      "decrypt the signing key ("+outFile("extracted.sig.plain")+")")

   flag.Parse()

   n := 0
   for _, on := range []bool{*step1, *step2, *step3, *step4} {
      if on {
         n++
      }
   }
   switch {
   case n == 0:
      fmt.Fprintln(os.Stderr, "prkf: no step selected")
      flag.Usage()
      os.Exit(2)
   case n > 1:
      fmt.Fprintln(os.Stderr, "prkf: select exactly one of -1 -2 -3 -4")
      os.Exit(2)
   }

   if err := ensureOutDir(); err != nil {
      fmt.Fprintf(os.Stderr, "prkf: %v\n", err)
      os.Exit(1)
   }

   var err error
   switch {
   case *step1:
      err = cmdCert(flag.Args())
   case *step2:
      err = cmdKeys(flag.Args())
   case *step3:
      err = cmdFindSub(flag.Args())
   case *step4:
      err = cmdDecrypt(flag.Args())
   }
   if err != nil {
      fmt.Fprintln(os.Stderr, err)
      os.Exit(1)
   }
}

// outFile returns the path inside outDir for a pipeline-written file.
func outFile(name string) string {
   return filepath.Join(outDir, name)
}

// u32be reads a big-endian uint32 at off, reporting whether it fit.
func u32be(buf []byte, off int) (uint32, bool) {
   if off < 0 || off+4 > len(buf) {
      return 0, false
   }
   return binary.BigEndian.Uint32(buf[off:]), true
}

// workerMain probes exactly one descriptor and exits. Its whole output is the
// RESULT line the driver parses; nothing is written to disk.
//
// It runs on a private FlagSet so that -one never shows up in the usage text
// of the four real steps.
func workerMain(argv []string) {
   fs := flag.NewFlagSet("prkf -one", flag.ContinueOnError)
   fs.SetOutput(os.Stderr)
   one := fs.String("one", "", "descriptor VA (hex) to probe")

   if err := fs.Parse(argv); err != nil {
      os.Exit(2)
   }
   if fs.NArg() != 0 {
      fmt.Fprintln(os.Stderr, "prkf -one: takes no positional arguments")
      os.Exit(2)
   }

   v, err := strconv.ParseUint(*one, 0, 32)
   if err != nil {
      fmt.Fprintf(os.Stderr, "prkf -one: bad value %q: %v\n", *one, err)
      os.Exit(2)
   }

   runOne(uint32(v)) // never returns: emit() exits
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
