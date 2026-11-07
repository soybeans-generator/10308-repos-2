// main.go begin
//go:build windows

// prkf is the PlayReady key-extraction pipeline: seven steps, eight files, one
// binary, one package, one folder.
//
//   prkf -1   extract.go     carve the CHAI chain, extract the key components
//   prkf -2   signing.go     locate the signing-key routine descriptor
//   prkf -3   signing.go     decrypt the signing key
//   prkf -4   oracle.go      build the nibble oracle
//   prkf -5   image.go       decrypt the Warbird image
//   prkf -6   nibblemap.go   derive oracle_map.json
//   prkf -7   plainkey.go    derive extracted.enc.plain
//
// warbird.go is the eighth file and holds no step: the Warbird descriptor
// format, the kernel call ABI, and the probe child that -2 re-executes.
//
// # DATA FLOW
//
// Two branches leave -1 and never meet again:
//
//   -1 -> -2 -> -3                  the signing key
//   -1 -> -4, -5 -> -6 -> -7        the encryption key
//
// Every artefact lives under outDir (testdata/). Each name is declared once, at
// the end of this file, so no step spells a path and no two can disagree.
//
//   in   msprcore.bla          the PlayReady sample, put here by hand
//   -1   extracted.cert        carved CHAI chain
//   -1   extracted.sig.pub     signing public key
//   -1   extracted.sig.prv     signing private component, 32 B, obfuscated
//   -1   extracted.enc.pub     encryption public key
//   -1   extracted.enc.prv     encryption private component, 65 B
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
// dllPath is the one path outside outDir. The module is read, hashed and
// mapped where Windows installed it, never copied: a descriptor is an RVA into
// that image, so the bytes hashed and the image executed must be the same one.
//
// # CHILD PROCESSES
//
// Three steps re-execute this binary rather than working in-process:
//
//   -2  one child per candidate descriptor, selected by PRKF_PROBE_DESC
//   -6  one child per (set, licence) sweep, selected by the "sweep" argument
//   -7  one child per (stage 1, stage 2) trial, selected by "s1"/"s2"
//
// The first is an environment variable, so `prkf -h` lists the seven steps and
// nothing else; the other two are positional, so the command line surface stays
// at exactly -1 through -7. See warbird.go for why the -2 probe must be its own
// process.
//
// Run the steps in order, from the same working directory. `rm -rf testdata`
// throws the whole run away, including the sample.
package main

import (
   "flag"
   "fmt"
   "os"
   "path/filepath"
)

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

func main() {
   // A probe child spawned by -2 announces itself through the environment, so
   // it needs no flag and no argument. Checked first, before the FlagSet
   // exists, so it never appears in the usage text.
   if va, ok := probeTarget(); ok {
      runOne(va) // never returns: emit() exits
      return
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

// main.go end
