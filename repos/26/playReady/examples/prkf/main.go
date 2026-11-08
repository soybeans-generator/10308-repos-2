// main.go begin
//go:build windows

// prkf is the PlayReady key-extraction pipeline: seven steps, eight files, one
// binary, one package, one folder.
//
//   prkf -1   signing.go     locate the signing-key routine descriptor   DLL
//   prkf -2   warbird.go     decrypt the Warbird image                   DLL
//   prkf -3   nibblemap.go   derive the nibble permutation               DLL
//   prkf -4   stages.go      find the (stage 1, stage 2) pairing         DLL
//   prkf -5   main.go        carve the CHAI chain, extract key components BLA
//   prkf -6   signing.go     decrypt the signing key                     BLA
//   prkf -7   plainkey.go    derive the encryption key                   BLA
//
// Four files hold no step of their own: warbird.go is the descriptor format, the
// PE census and the span carving; kernel.go is the kernel ABI, the fault handler
// and the build profile; child.go is every body this binary re-executes and the
// plumbing they share; plainkey.go is the apply path -7 uses.
//
// # RUN ORDER IS FLAG ORDER
//
// The BLA is required from -4 onward, because finding the pairing means running a
// sample's real key through the stage routines; -4 carves the key components out
// of msprcore.bla itself when -5 has not written them yet.
//
// That dependency does not propagate. Each routine family has its own chain, so -4
// records the pairing for its own sample's family and -7 discovers any family it
// has no pairing for, with its own sample, then caches it.
//
//   -5 -> -1 -> -6                  the signing key
//   -5 -> -2 -> -3 -> -4 -> -7      the encryption key
//
// Every artefact lives under outDir (testdata/); each name is declared once at the
// end of this file. dllPath is the one path outside it.
//
// # NO CONCURRENCY
//
// There are no goroutines, channels or mutexes anywhere in this program. Speed
// comes from doing less work per child, not from running children in parallel.
// main is the only place that calls os.Exit (see wbVEH); every step prints
// `elapsed`.
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
   "time"
)

// ------------------------------------------------- first half: the CHAI chain

// certHdr is the fixed part of one certificate entry, read in four places in
// parseChain, so it earns a package-level name. The CHAI header's own size is used
// twice, both inside parseChain, and is a local there.
const certHdr = 16 // magic(4) version(4) total_length(4) certificate_length(4)

// ------------------------------------------------------------------ manifest

// dllPath is the PlayReady module, read and mapped where Windows installed it. It
// stays outside outDir on purpose: a descriptor is an RVA into the mapped image,
// so the bytes hashed and the image the Warbird gate executes must be the same
// module, and a copy in testdata/ is a different mapping.
const dllPath = `C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll`

// outDir is the one directory the pipeline uses: the sample it reads and every
// file it writes. Nothing else should spell a directory: read and write through
// dataFile, or through one of the manifest paths below.
const outDir = "testdata"

// Every file the pipeline reads or writes, named once, so a rename is one line
// here rather than a hunt through eight files.
//
// They are vars, not consts, only because dataFile resolves outDir; outDir is
// itself a constant, so the values are fixed for the life of the process.
var (
   // The pipeline's one input, read by -5 and, when -5 has not run, by -4 and -7.
   corePath = dataFile("msprcore.bla")

   // --- DLL phase -------------------------------------------------------
   //
   // prsubs.json is keyed by the DLL sha256, so this half of the cache was
   // always sound; it is not folded into the profile because -1 and -6 need
   // nothing else from it.
   prsubsPath  = dataFile("prsubs.json")
   scanLogPath = dataFile("findprsub.txt")

   imgPath    = dataFile("wbtool_img.bin")
   imgLogPath = dataFile("decrypt_img.txt")

   // The build profile: everything the DLL phase derives, keyed by the DLL's
   // SHA-256. See kernel.go for why it is keyed by the DLL, not the image.
   profilePath = dataFile("dllprof.json")

   mapLogPath   = dataFile("derive_map.txt")
   stageLogPath = dataFile("derive_stages.txt")

   // --- BLA phase -------------------------------------------------------
   //
   // -5 outputs. -4 and -7 carve the enc pair themselves when absent.
   certPath   = dataFile("extracted.cert")
   sigPubPath = dataFile("extracted.sig.pub")
   sigPrvPath = dataFile("extracted.sig.prv")
   encPubPath = dataFile("extracted.enc.pub")
   encPrvPath = dataFile("extracted.enc.prv")

   sigPlainPath = dataFile("extracted.sig.plain")
   encPlainPath = dataFile("extracted.enc.plain")
   plainLogPath = dataFile("derive_plain.txt")

   // The nibble oracle. Not a step: nibblemap.go builds it on demand when -3
   // finds it absent. `rm -rf` this directory to force a rebuild.
   oracleDir = dataFile("oracle")
)

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
   magic := []byte("CHAI")
   var candidates []*chain
   for i := 0; ; {
      j := bytes.Index(buf[i:], magic)
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
   fmt.Printf("\nbytes 0x%x..0x%x (before CHAI):\n  % x\n", lo, base, buf[lo:base])
   switch {
   case base < 4:
      fmt.Println("  (chain starts before offset 4 - no length prefix possible)")
   case ch.prefixOK:
      fmt.Printf("u32be at CHAI-4 = 0x%08x == chain length -> PRKF length-prefix confirmed\n", ch.prefix)
   default:
      fmt.Printf("u32be at CHAI-4 = 0x%08x != chain length (%d) -> not a PRKF-length-prefixed span\n",
         ch.prefix, totalLength)
   }

   if err := os.WriteFile(certPath, blob, 0o644); err != nil {
      return err
   }
   fmt.Printf("\nwrote %s (%d bytes)\n", certPath, len(blob))
   return nil
}

// cmdExtract implements prkf -5: carve the chain, then extract the keys.
//
// It is also what -4 and -7 call when the enc pair is absent, which is why it is
// idempotent: writing the same bytes twice is the price of letting the steps run
// in flag order.
func cmdExtract() error {
   if err := cmdCert(); err != nil {
      return err
   }
   fmt.Println()
   return cmdKeys()
}

// cmdKeys parses the PRKF key-material section and writes the four key
// components. It re-reads corePath rather than taking buf from cmdCert: the two
// halves are independent, and neither holds state for the other.
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
   //     key. No field separates it from the other 32-byte record: ver/flags/
   //     z1/z2 are identical across all three and every pubkey occurs exactly
   //     twice, so neither header values nor reference counts discriminate.
   i := -1
   for j, r := range recs {
      if r == enc {
         i = j
         break
      }
   }
   if i <= 0 {
      return fmt.Errorf("no 32-byte record precedes the encryption key")
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

// dataFile returns the path inside outDir for a pipeline file, whether the
// pipeline reads it or writes it. Both directions go through here, so no step has
// to know the directory's name and no file can escape it.
func dataFile(name string) string {
   return filepath.Join(outDir, name)
}

// ensureOutDir creates outDir if it does not exist. Called once from main before
// dispatch, so no step has to care.
func ensureOutDir() error {
   return os.MkdirAll(outDir, 0o755)
}

// ------------------------------------------------------------------- dispatch

func main() {
   // A probe child spawned by -1 announces itself through the environment, so it
   // needs no flag and no argument. Checked first, before the FlagSet exists, so
   // it never appears in the usage text.
   if vas, ok, err := probeTarget(); ok {
      if err != nil {
         fmt.Fprintf(os.Stderr, "prkf: %v\n", err)
         os.Exit(2)
      }
      os.Exit(runProbes(vas))
   }

   step1 := flag.Bool("1", false, "DLL:  locate the signing-key routine")
   step2 := flag.Bool("2", false, "DLL:  decrypt the Warbird image")
   step3 := flag.Bool("3", false, "DLL:  derive the nibble permutation")
   step4 := flag.Bool("4", false, "DLL:  find the (stage 1, stage 2) pairing")
   step5 := flag.Bool("5", false, "BLA:  carve the CHAI chain and the four key components")
   step6 := flag.Bool("6", false, "BLA:  decrypt the signing key")
   step7 := flag.Bool("7", false, "BLA:  derive the encryption key")

   flag.Parse()

   n := 0
   for _, on := range []bool{*step1, *step2, *step3, *step4, *step5, *step6, *step7} {
      if on {
         n++
      }
   }
   switch {
   case n == 0:
      flag.Usage()
      os.Exit(2)
   case n > 1:
      fmt.Fprintln(os.Stderr, "prkf: select exactly one of -1 through -7")
      os.Exit(2)
   }

   // -1, -2, -5 and -6 take no arguments at all. -3 and -4 own their positional
   // worker modes and -7 owns -4's trial children, so those three receive
   // whatever follows the flag verbatim and validate it themselves; a blanket
   // NArg check here would break their children.
   noArgs := func(stage string) bool {
      if flag.NArg() == 0 {
         return true
      }
      fmt.Fprintf(os.Stderr, "prkf %s: unexpected argument %q: this step takes no arguments\n",
         stage, flag.Arg(0))
      return false
   }

   if err := ensureOutDir(); err != nil {
      fmt.Fprintf(os.Stderr, "prkf: %v\n", err)
      os.Exit(1)
   }

   // runStep times one top-level step, prints its duration, and exits with the
   // step's code. It cannot be a deferred timer inside each stage: main calls
   // os.Exit with the stage's return value, which unwinds no frames.
   runStep := func(fn func() int) {
      t0 := time.Now()
      code := fn()
      fmt.Printf("elapsed %s\n", time.Since(t0).Round(time.Millisecond))
      os.Exit(code)
   }

   // errCode folds an error-returning step into the code runStep reports.
   errCode := func(err error) int {
      if err == nil {
         return 0
      }
      fmt.Fprintln(os.Stderr, err)
      return 1
   }

   switch {
   case *step1:
      if !noArgs("-1") {
         os.Exit(2)
      }
      runStep(func() int { return errCode(cmdFindSub()) })
   case *step2:
      if !noArgs("-2") {
         os.Exit(2)
      }
      runStep(stageDecryptImg)
   case *step3:
      // A positional argument means this process is a sweep child. Its stdout is
      // parsed, so it exits on the raw code with no duration line.
      if flag.NArg() > 0 {
         os.Exit(stageDeriveMap(flag.Args()))
      }
      runStep(func() int { return stageDeriveMap(nil) })
   case *step4:
      if flag.NArg() > 0 {
         os.Exit(stageFindStages(flag.Args()))
      }
      runStep(func() int { return stageFindStages(nil) })
   case *step5:
      if !noArgs("-5") {
         os.Exit(2)
      }
      runStep(func() int { return errCode(cmdExtract()) })
   case *step6:
      if !noArgs("-6") {
         os.Exit(2)
      }
      runStep(func() int { return errCode(cmdDecrypt()) })
   default:
      if !noArgs("-7") {
         os.Exit(2)
      }
      runStep(func() int { return stageDerivePlain(nil) })
   }
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
   prefix      uint32
   prefixOK    bool
}

// parseChain is a self-validating parse of a CHAI chain at base. Only the header
// fields that are actually used are decoded: the certificate version is not
// needed to locate anything, and the per-certificate lengths are consumed in the
// loop rather than retained.
func parseChain(buf []byte, base int) (*chain, bool) {
   // magic(4) version(4) total_length(4) flags(4) cert_count(4)
   const chaiHdr = 20

   if base < 0 || base+4 > len(buf) || !bytes.Equal(buf[base:base+4], []byte("CHAI")) {
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

   // The length prefix lives in the four bytes before the magic. u32be rejects
   // off < 0, so a chain near the start of the file simply has none.
   if p, ok := u32be(buf, base-4); ok {
      c.prefix = p
      c.prefixOK = p == totalLength
   }
   return c, true
}

// keyRecord is one 0x100f record's public and private components. The lengths are
// len(pub) and len(priv): the record carries them as u32 fields, but every
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
   return &keyRecord{off: ps, pub: pub, priv: buf[q+12 : q+12+privlen]}
}

// section is a parsed PRKF section header. Only the type and the payload span are
// retained: the tag, offset and total size are used while walking and have no
// consumer afterwards.
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

// main.go end
