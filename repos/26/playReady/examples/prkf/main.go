// main.go begin
//go:build windows

// prkf is the PlayReady key-extraction pipeline: seven steps, eight files, one
// binary, one package, one folder.
//
//   prkf -1   main.go        carve the CHAI chain, extract the key components
//   prkf -2   signing.go     locate the signing-key routine descriptor
//   prkf -3   signing.go     decrypt the signing key
//   prkf -4   oracle.go      build the nibble oracle
//   prkf -5   image.go       decrypt the Warbird image
//   prkf -6   nibblemap.go   derive oracle_map.json
//   prkf -7   plainkey.go    derive extracted.enc.plain
//
// Three files hold no step of their own: warbird.go is the descriptor format,
// the PE census, the span and block carving, the kernel ABI, the page patch and
// the fault handler; child.go is the two bodies this binary re-executes and the
// trace plumbing they share; main.go is the manifest, the dispatch, and -1.
//
// A step owns its driver, and a file may hold about 25 KB. The two steps whose
// driver and child together exceed that (-2 and -7) put the child in child.go -
// the split -2 needs anyway, since a fault in a descriptor's code kills the
// process. -6 keeps its sweep child: driver and worker still fit.
//
// # DATA FLOW
//
// Two branches leave -1 and never meet again:
//
//   -1 -> -2 -> -3                  the signing key
//   -1 -> -4, -5 -> -6 -> -7        the encryption key
//
// Every artefact lives under outDir (testdata/), and each name is declared once
// at the end of this file, so no step spells a path and no two can disagree:
//
//   in   msprcore.bla          the PlayReady sample, put here by hand
//   -1   extracted.{cert,sig.pub,sig.prv,enc.pub,enc.prv}
//   -2   prsubs.json           signing routine descriptor, keyed by DLL sha256
//   -2   findprsub.txt         per-descriptor probe log
//   -3   extracted.sig.plain   signing private scalar, 32 B, plain
//   -4   oracle/key_NN.pub     nibble oracle public keys, 15 files
//   -4   oracle/lic_NN.blob    nibble oracle licence blobs, 15 files
//   -5   wbtool_img.bin        decrypted image, RVA == file offset
//   -5   decrypt_img.txt       per-block decrypt log
//   -6   oracle_map.json       nibble permutation + magic sequence
//   -6   derive_map.txt        sweep log
//   -7   extracted.enc.plain   encryption private scalar, 32 B, plain
//   -7   derive_plain.txt      trial log
//
// dllPath is the one path outside outDir. The module is read, hashed and mapped
// where Windows installed it, never copied: a descriptor is an RVA into that
// image, so the bytes hashed and the image executed must be the same one.
//
// # CHILD PROCESSES
//
// Three steps re-execute this binary rather than working in-process: -2 one
// child per candidate descriptor, selected by PRKF_PROBE_DESC; -6 one child per
// (set, licence) sweep, selected by the "sweep" argument; -7 one child per
// (stage 1, stage 2) trial, selected by "s1"/"s2". The first is an environment
// variable, so `prkf -h` lists the seven steps and nothing else; the other two
// are positional, so the command line surface stays at exactly -1 through -7.
//
// # EXIT CODES
//
// main is the only place that calls os.Exit, with one exception documented at
// wbVEH: the callback, which has no caller to return to and must not panic.
// Every worker and stage returns its code instead. Run the steps in order, from
// the same working directory; `rm -rf testdata` throws the whole run away.
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
)

// ------------------------------------------------- first half: the CHAI chain

// certHdr is the fixed part of one certificate entry, and it is read in four
// places in parseChain, so it earns a package-level name. The CHAI header's own
// size is used twice, both inside parseChain, and is a local there.
const certHdr = 16 // magic(4) version(4) total_length(4) certificate_length(4)

// ------------------------------------------------------------------ manifest

// dllPath is the PlayReady module, read and mapped where Windows installed it.
// It is the only path in the program outside outDir, and it stays outside on
// purpose: the descriptor is an RVA into the mapped image, so the bytes hashed
// here and the image the Warbird gate executes from have to be the same module,
// and a copy loaded out of testdata/ is a different mapping that the gate is
// not documented to accept.
const dllPath = `C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll`

// outDir is the one directory the pipeline uses: the sample it reads and every
// file it writes. Inputs are fixtures here, not in the working directory, so a
// run touches nothing outside it and can be discarded as a unit.
//
// Nothing else in the pipeline should spell a directory: read and write through
// dataFile, or through one of the manifest paths below.
const outDir = "testdata"

// Every file the pipeline reads or writes, named once. The steps below this
// file use these names and nothing else, so a rename is one line here rather
// than a hunt through seven files.
//
// They are vars, not consts, only because dataFile resolves outDir; outDir is
// itself a constant, so the values are fixed for the life of the process.
var (
   // The pipeline's one input, read by both halves of -1.
   corePath = dataFile("msprcore.bla")

   // -1 outputs.
   certPath   = dataFile("extracted.cert")
   sigPubPath = dataFile("extracted.sig.pub")
   sigPrvPath = dataFile("extracted.sig.prv")
   encPubPath = dataFile("extracted.enc.pub")
   encPrvPath = dataFile("extracted.enc.prv")

   // -2 -> -3.
   prsubsPath  = dataFile("prsubs.json")
   scanLogPath = dataFile("findprsub.txt")

   // -3 output.
   sigPlainPath = dataFile("extracted.sig.plain")

   // -4 output directory: oracle/key_NN.pub and oracle/lic_NN.blob.
   oracleDir = dataFile("oracle")

   // -5 -> -6, -7.
   imgPath    = dataFile("wbtool_img.bin")
   imgLogPath = dataFile("decrypt_img.txt")

   // -6 -> -7.
   mapPath    = dataFile("oracle_map.json")
   mapLogPath = dataFile("derive_map.txt")

   // -7 output.
   encPlainPath = dataFile("extracted.enc.plain")
   plainLogPath = dataFile("derive_plain.txt")
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

// cmdExtract implements prkf -1: carve the chain, then extract the keys.
//
// The two halves read the same file and write disjoint outputs, so the order
// is arbitrary. Carving runs first because it is the cheaper structural check
// on the sample and its failure message is more specific than "not a PRKF".
//
// A failure in either half aborts the step: a run that produced a chain but no
// keys is not a state any later step can use.
func cmdExtract() error {
   if err := cmdCert(); err != nil {
      return err
   }
   fmt.Println() // separate the two halves' reports
   return cmdKeys()
}

// ---------------------------------------------- second half: the key records

// cmdKeys parses the PRKF key-material section and writes the four key
// components: sigPubPath, sigPrvPath (32 bytes, still obfuscated), encPubPath
// and encPrvPath (65 bytes). It re-reads corePath rather than taking buf from
// cmdCert: the two halves are independent, and neither holds state for the
// other.
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

// dataFile returns the path inside outDir for a pipeline file, whether the
// pipeline reads it or writes it. Both directions go through here, so no step
// has to know the directory's name and no file can escape it.
func dataFile(name string) string {
   return filepath.Join(outDir, name)
}

// ensureOutDir creates outDir if it does not exist. Called once from main
// before dispatch, so no step has to care.
func ensureOutDir() error {
   return os.MkdirAll(outDir, 0o755)
}

// ------------------------------------------------------------------- dispatch

func main() {
   // A probe child spawned by -2 announces itself through the environment, so
   // it needs no flag and no argument. Checked first, before the FlagSet
   // exists, so it never appears in the usage text. A malformed value is an
   // error out of probeTarget, not an exit inside it.
   if va, ok, err := probeTarget(); ok {
      if err != nil {
         fmt.Fprintf(os.Stderr, "prkf: %v\n", err)
         os.Exit(2)
      }
      os.Exit(runOne(va))
   }

   step1 := flag.Bool("1", false,
      "carve the CHAI chain ("+certPath+") and the four key components")
   step2 := flag.Bool("2", false,
      "locate the signing-key routine ("+prsubsPath+", "+scanLogPath+")")
   step3 := flag.Bool("3", false,
      "decrypt the signing key ("+sigPlainPath+")")
   step4 := flag.Bool("4", false,
      "build the nibble oracle ("+oracleDir+")")
   step5 := flag.Bool("5", false,
      "decrypt the Warbird image ("+imgPath+", "+imgLogPath+")")
   step6 := flag.Bool("6", false,
      "derive the nibble map ("+mapPath+", "+mapLogPath+")")
   step7 := flag.Bool("7", false,
      "derive the encryption key ("+encPlainPath+", "+plainLogPath+")")

   flag.Parse()

   n := 0
   for _, on := range []bool{*step1, *step2, *step3, *step4, *step5, *step6, *step7} {
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
      fmt.Fprintln(os.Stderr, "prkf: select exactly one of -1 through -7")
      os.Exit(2)
   }

   // -1..-5 take no arguments at all. -6 and -7 own their positional worker
   // modes, so they receive whatever follows the flag verbatim and validate it
   // themselves; a blanket NArg check here would break their children.
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

   var err error
   switch {
   case *step1:
      if !noArgs("-1") {
         os.Exit(2)
      }
      err = cmdExtract()
   case *step2:
      if !noArgs("-2") {
         os.Exit(2)
      }
      err = cmdFindSub()
   case *step3:
      if !noArgs("-3") {
         os.Exit(2)
      }
      err = cmdDecrypt()
   case *step4:
      if !noArgs("-4") {
         os.Exit(2)
      }
      os.Exit(stageMakeOracle())
   case *step5:
      if !noArgs("-5") {
         os.Exit(2)
      }
      os.Exit(stageDecryptImg())
   case *step6:
      os.Exit(stageDeriveMap(flag.Args()))
   default:
      os.Exit(stageDerivePlain(flag.Args()))
   }
   if err != nil {
      fmt.Fprintln(os.Stderr, err)
      os.Exit(1)
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

   c := &chain{
      base:        base,
      totalLength: totalLength,
      flags:       flags,
      certCount:   certCount,
   }

   end := base + int(totalLength)
   off := base + chaiHdr

   for n := uint32(0); n < certCount; n++ {
      if off+certHdr > end || !bytes.Equal(buf[off:off+4], []byte("CERT")) {
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

// main.go end
