// main.go begin
//go:build windows

// prkf is the PlayReady key-extraction pipeline: three steps, one binary, one
// package, one folder. Each step is selected by a flag:
//
//   prkf -1    extract.go   carve the CHAI chain, extract key components
//   prkf -2    findsub.go   locate the signing-key routine descriptor
//   prkf -3    decrypt.go   decrypt the signing key
//
// This file is only the driver: parse the flag, reject arguments, make the
// output directory, dispatch, and name the pipeline's one input. It holds no
// step logic.
//
// warbird.go holds the kernel call ABI that -2 and -3 share, and the probe
// child that -2 re-executes. The ABI constants (warbirdOp, argsLen, outOff,
// keyLen, probeEnv, probeTimeout) live there; dllPath lives in findsub.go,
// which owns the DLL the scan reads.
//
// Steps -1 and -2 of the old four-step pipeline are now one step. They read
// the same input (msprcore.bla) and write disjoint outputs; nothing downstream
// ever wanted the carved chain without the keys, so the split only forced an
// ordering rule on the caller.
//
// Run the steps in order, in one directory: -2 writes prsubs.json, -3 reads
// it, and -3 consumes what -1 wrote. Every file the pipeline creates lands in
// testdata/, so a run is disposable and the working directory stays clean.
//
// -2 also re-executes this binary, one child per candidate descriptor, to
// probe it. The child is selected by an environment variable rather than a
// flag or an argument, so `prkf -h` lists the three steps and nothing else.
// See warbird.go for why the probe must be a separate process.
package main

import (
   "flag"
   "fmt"
   "os"
   "path/filepath"
)

// corePath is the pipeline's one input. Both halves of prkf -1 read it, so it
// is named here, by the driver, rather than by either half.
const corePath = "msprcore.bla"

// outDir is where every file this program creates is written. Inputs are
// still read from the working directory (msprcore.bla); only outputs are
// redirected here.
//
// Nothing else in the pipeline should spell a directory: write through
// outFile so the whole run can be thrown away with `rm -rf testdata`.
const outDir = "testdata"

// cmdExtract implements prkf -1: carve the chain, then extract the keys.
//
// The two halves read the same file and write disjoint outputs, so the order
// is arbitrary. Carving runs first because it is the cheaper structural check
// on msprcore.bla and its failure message is more specific than "not a PRKF".
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
      "carve the CHAI chain ("+outFile("extracted.cert")+") and extract the key "+
         "components ("+outFile("extracted")+".{sig,enc}.{pub,prv})")
   step2 := flag.Bool("2", false,
      "locate the signing-key routine ("+outFile("prsubs.json")+", "+outFile("findprsub.txt")+")")
   step3 := flag.Bool("3", false,
      "decrypt the signing key ("+outFile("extracted.sig.plain")+")")

   flag.Parse()

   n := 0
   for _, on := range []bool{*step1, *step2, *step3} {
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
      fmt.Fprintln(os.Stderr, "prkf: select exactly one of -1 -2 -3")
      os.Exit(2)
   }

   // Checked once here rather than in each step: -1 runs two functions, so a
   // per-step check would be duplicated and would name the wrong step.
   if flag.NArg() != 0 {
      fmt.Fprintf(os.Stderr, "prkf: unexpected argument %q: no step takes arguments\n",
         flag.Arg(0))
      os.Exit(2)
   }

   if err := ensureOutDir(); err != nil {
      fmt.Fprintf(os.Stderr, "prkf: %v\n", err)
      os.Exit(1)
   }

   var err error
   switch {
   case *step1:
      err = cmdExtract()
   case *step2:
      err = cmdFindSub()
   case *step3:
      err = cmdDecrypt()
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

// main.go end
