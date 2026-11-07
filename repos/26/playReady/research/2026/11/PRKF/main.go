// main.go begin
//go:build windows

// prkf is the PlayReady key-extraction pipeline: seven steps across eight
// files, one binary, one package, one folder. Each step is selected by a flag:
//
//   prkf -1   extract.go     carve the CHAI chain, extract the key components
//   prkf -2   signing.go     locate the signing-key routine descriptor
//   prkf -3   signing.go     decrypt the signing key
//   prkf -4   oracle.go      build the nibble oracle
//   prkf -5   image.go       decrypt the Warbird image
//   prkf -6   nibblemap.go   derive oracle_map.json
//   prkf -7   plainkey.go    derive extracted.enc.plain
//
// warbird.go is the eighth file and holds no step: it is the kernel call ABI
// that -2 and -3 share, plus the probe child that -2 re-executes.
//
// This file is only the driver: parse the flag, reject arguments, make the
// testdata directory, dispatch, and name the pipeline's inputs. It holds no
// step logic.
//
// -2 and -3 share a file because they are one branch: -2 writes prsubs.json
// and -3 reads it, and the record is the whole interface between them.
//
// Run the steps in order, from the same working directory. -1 feeds both
// branches: -2 writes prsubs.json for -3 to read, and -1 writes the
// extracted.enc.{pub,prv} pair that -6 and -7 consume. -4 writes the oracle
// directory; -5 writes wbtool_img.bin, which -6 and -7 both read; -6 writes
// oracle_map.json, which -7 reads. Every path goes through dataFile or the
// step's own data constants, so the sample is read from testdata/ and
// everything the pipeline creates lands beside it. The working directory stays
// clean, and `rm -rf testdata` throws the whole run away - including the
// sample, which has to be put back before the next run.
//
// dllPath is the one path that is not under testdata/: the PlayReady module is
// read, hashed and mapped where Windows installed it. -5 reads the same module
// for the same reason.
//
// Three steps re-execute this binary rather than doing their work in-process:
//
//   -2  one child per candidate descriptor, selected by PRKF_PROBE_DESC
//   -6  one child per (set, licence) sweep, selected by the "sweep" argument
//   -7  one child per (stage 1, stage 2) trial, selected by "s1"/"s2"
//
// The first is an environment variable, so `prkf -h` lists the seven steps and
// nothing else; the other two are positional arguments, so the command line
// surface stays at exactly -1 through -7. See warbird.go for why the -2 probe
// must be a separate process.
package main

import (
   "flag"
   "fmt"
   "os"
   "path/filepath"
)

// outDir is the one directory the pipeline uses: the sample it reads and every
// file it writes. Inputs are fixtures here, not in the working directory, so a
// run touches nothing outside it and can be discarded as a unit.
//
// Nothing else in the pipeline should spell a directory: read and write
// through dataFile.
const outDir = "testdata"

// corePath is the pipeline's one input, read from testdata/ like every other
// path. Both halves of prkf -1 read it, so it is named here, by the driver,
// rather than by either half.
//
// It is a var, not a const, only because dataFile resolves outDir; outDir is
// itself a constant, so the value is fixed for the life of the process.
var corePath = dataFile("msprcore.bla")

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
   // A probe child spawned by -2 announces itself through the environment,
   // so it needs no flag and no argument. Checked first, before the FlagSet
   // exists, so it never appears in the usage text.
   if va, ok := probeTarget(); ok {
      runOne(va) // never returns: emit() exits
      return
   }

   step1 := flag.Bool("1", false,
      "carve the CHAI chain ("+dataFile("extracted.cert")+") and extract the key "+
         "components ("+dataFile("extracted")+".{sig,enc}.{pub,prv})")
   step2 := flag.Bool("2", false,
      "locate the signing-key routine ("+dataFile("prsubs.json")+", "+dataFile("findprsub.txt")+")")
   step3 := flag.Bool("3", false,
      "decrypt the signing key ("+dataFile("extracted.sig.plain")+")")
   step4 := flag.Bool("4", false,
      "build the nibble oracle ("+dataFile("oracle")+"/key_NN.pub, "+dataFile("oracle")+"/lic_NN.blob)")
   step5 := flag.Bool("5", false,
      "decrypt the Warbird image ("+dataFile("wbtool_img.bin")+", "+dataFile("decrypt_img.txt")+")")
   step6 := flag.Bool("6", false,
      "derive the nibble map ("+dataFile("oracle_map.json")+", "+dataFile("derive_map.txt")+")")
   step7 := flag.Bool("7", false,
      "derive the encryption key ("+dataFile("extracted.enc.plain")+", "+dataFile("derive_plain.txt")+")")

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

   // Checked once here rather than in each step: -1 runs two functions, so a
   // per-step check would be duplicated and would name the wrong step.
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
