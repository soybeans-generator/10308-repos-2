// main.go begin
//go:build windows

// prkf: six steps, one binary, one package.
//
//   prkf -1   signing.go     locate the signing-key routine descriptor     DLL
//   prkf -2   warbird.go     decrypt the Warbird image                     DLL
//   prkf -3   nibblemap.go   derive the nibble permutation                 DLL
//   prkf -4   main.go        carve the CHAI chain, extract key components  BLA
//   prkf -5   signing.go     decrypt the signing key                       BLA
//   prkf -6   plainkey.go    derive the encryption key                     BLA
//
// -1..-3 read only the DLL; -4..-6 read only the sample. Every artefact lives under
// outDir, every path is declared once at the end of this file, and dllPath is the one
// path outside it.
//
// No goroutines, channels or mutexes. main is the only place that calls os.Exit outside
// wbVEH.
package main

import (
   "bytes"
   "encoding/binary"
   "encoding/hex"
   "errors"
   "flag"
   "fmt"
   "os"
   "path/filepath"
   "strings"
   "time"
)

// certHdr is the fixed part of one certificate entry: magic(4) version(4)
// total_length(4) certificate_length(4).
const certHdr = 16

// dllPath is the PlayReady module, read and mapped where Windows installed it. It stays
// outside outDir: a descriptor is an RVA into the mapped image, so the bytes hashed and
// the image the Warbird gate executes must be the same module.
const dllPath = `C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll`

// outDir is the one directory the pipeline uses: the sample it reads and every file it
// writes. Read and write through dataFile, never by spelling a path.
const outDir = "testdata"

var (
   corePath = dataFile("msprcore.bla") // the pipeline's one input, read by -4 and -6

   // --- DLL phase -------------------------------------------------------
   prsubsPath  = dataFile("prsubs.json")
   scanLogPath = dataFile("findprsub.txt")
   imgPath     = dataFile("wbtool_img.bin")
   imgLogPath  = dataFile("decrypt_img.txt")
   profilePath = dataFile("dllprof.json") // everything -1..-3 derive, keyed by DLL sha
   mapLogPath  = dataFile("derive_map.txt")

   // --- BLA phase -------------------------------------------------------
   certPath   = dataFile("extracted.cert")
   sigPubPath = dataFile("extracted.sig.pub")
   sigPrvPath = dataFile("extracted.sig.prv")
   encPubPath = dataFile("extracted.enc.pub")
   encPrvPath = dataFile("extracted.enc.prv")

   sigPlainPath = dataFile("extracted.sig.plain")
   encPlainPath = dataFile("extracted.enc.plain")
   plainLogPath = dataFile("derive_plain.txt")

   // The nibble oracle. Not a step: -3 builds it when absent. `rm -rf` to force.
   oracleDir = dataFile("oracle")
)

// cmdCert carves the CHAI certificate chain out of corePath and writes it to certPath.
// A candidate must tile its own certificate entries exactly, and a chain whose preceding
// length prefix matches its total length is preferred.
func cmdCert() error {
   if fi, err := os.Stat(corePath); err != nil || !fi.Mode().IsRegular() {
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

   blob := buf[ch.base : ch.base+int(ch.totalLength)]

   lo := max(ch.base-16, 0)
   fmt.Printf("\nbytes 0x%x..0x%x (before CHAI):\n  % x\n", lo, ch.base, buf[lo:ch.base])
   switch {
   case ch.base < 4:
      fmt.Println("  (chain starts before offset 4 - no length prefix possible)")
   case ch.prefixOK:
      fmt.Printf("u32be at CHAI-4 = 0x%08x == chain length -> PRKF length-prefix confirmed\n", ch.prefix)
   default:
      fmt.Printf("u32be at CHAI-4 = 0x%08x != chain length (%d) -> not a PRKF-length-prefixed span\n",
         ch.prefix, ch.totalLength)
   }

   if err := os.WriteFile(certPath, blob, 0o644); err != nil {
      return err
   }
   fmt.Printf("\nwrote %s (%d bytes)\n", certPath, len(blob))
   return nil
}

// cmdExtract is -4: carve the chain, then extract the keys. Idempotent, because -6
// calls it when the enc pair is absent.
func cmdExtract() error {
   if err := cmdCert(); err != nil {
      return err
   }
   fmt.Println()
   return cmdKeys()
}

// cmdKeys parses the PRKF key-material section and writes the four key components. It
// re-reads corePath rather than taking buf from cmdCert: the two halves are independent
// and neither holds state for the other.
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
         r.off, len(r.pub), len(r.priv), hex.EncodeToString(head))
   }

   // The encryption key is the unique record with a 65-byte private component; the
   // signing key is the record immediately before it. No field separates it from the
   // other 32-byte record: ver/flags/z1/z2 are identical across all three and every
   // pubkey occurs exactly twice.
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

// dataFile returns the path inside outDir for a pipeline file, whether the pipeline
// reads it or writes it.
func dataFile(name string) string {
   return filepath.Join(outDir, name)
}

// errStep adapts an error-returning step to the exit code the dispatcher reports.
func errStep(fn func() error) func() int {
   return func() int {
      if err := fn(); err != nil {
         fmt.Fprintln(os.Stderr, err)
         return 1
      }
      return 0
   }
}

// ------------------------------------------------------------------- dispatch

func main() {
   // A child is this binary re-executed with its mode in the environment and no
   // arguments at all. Checked before the FlagSet exists.
   if code, ok, err := childMode(); ok {
      if err != nil {
         fmt.Fprintf(os.Stderr, "prkf: %v\n", err)
         os.Exit(2)
      }
      os.Exit(code)
   }

   var (
      doFind    = flag.Bool("1", false, "DLL:  locate the signing-key routine")
      doImg     = flag.Bool("2", false, "DLL:  decrypt the Warbird image")
      doMap     = flag.Bool("3", false, "DLL:  derive the nibble permutation")
      doExtract = flag.Bool("4", false, "BLA:  carve the CHAI chain and the four key components")
      doDecrypt = flag.Bool("5", false, "BLA:  decrypt the signing key")
      doPlain   = flag.Bool("6", false, "BLA:  derive the encryption key")
   )
   flag.Parse()

   var run func() int
   n := 0
   if *doFind {
      n++
      run = errStep(cmdFindSub)
   }
   if *doImg {
      n++
      run = stageDecryptImg
   }
   if *doMap {
      n++
      run = dmDeriveMap
   }
   if *doExtract {
      n++
      run = errStep(cmdExtract)
   }
   if *doDecrypt {
      n++
      run = errStep(cmdDecrypt)
   }
   if *doPlain {
      n++
      run = dpDerive
   }

   if n == 0 {
      flag.Usage()
      os.Exit(2)
   }
   if n > 1 {
      fmt.Fprintln(os.Stderr, "prkf: select exactly one of -1 through -6")
      os.Exit(2)
   }

   if err := os.MkdirAll(outDir, 0o755); err != nil {
      fmt.Fprintf(os.Stderr, "prkf: %v\n", err)
      os.Exit(1)
   }

   // The elapsed line cannot be a deferred timer inside the step: main exits with the
   // step's code, which unwinds no frames.
   t0 := time.Now()
   code := run()
   fmt.Printf("elapsed %s\n", time.Since(t0).Round(time.Millisecond))
   os.Exit(code)
}

// ------------------------------------------------------------------ the sample

type chain struct {
   base        int
   totalLength uint32
   flags       uint32
   certCount   uint32
   prefix      uint32
   prefixOK    bool
}

// parseChain is a self-validating parse of a CHAI chain at base. One bounds check
// covers the whole fixed header, so the three fields below are read directly.
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

// ------------------------------------------------------------------- the step log

// stepLog is the log -2, -3 and -6 keep: every line goes to the terminal as it is
// produced and to the step's file when the step ends, so no return path can leave the
// file unwritten. -1 does not use it: its log must be on disk before the next statement
// runs, because it is the only evidence a stalled scan leaves behind.
type stepLog struct {
   path  string
   lines []string
}

func newStepLog(path string) *stepLog { return &stepLog{path: path} }

// Failf logs a FATAL line and returns the code for it, so a step's every failure is one
// `return lg.Failf(...)`.
func (l *stepLog) Failf(f string, a ...any) int {
   l.Printf("FATAL: "+f, a...)
   return 1
}

// Finish writes the log and folds a write failure into the step's exit code:
// `defer lg.Finish(&code)`.
func (l *stepLog) Finish(code *int) {
   if err := os.WriteFile(l.path, []byte(strings.Join(l.lines, "\n")+"\n"), 0o644); err != nil {
      fmt.Fprintf(os.Stderr, "prkf: %s: %v\n", l.path, err)
      *code = 1
   }
}

func (l *stepLog) Printf(f string, a ...any) {
   s := fmt.Sprintf(f, a...)
   l.lines = append(l.lines, s)
   fmt.Println(s)
}

// main.go end
