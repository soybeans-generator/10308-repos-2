// main.go begin
// One binary, one package, seven steps.
//
//   -1   signing.go    DLL   locate the signing-key routine
//   -2   warbird.go    DLL   decrypt the Warbird image
//   -3   nibblemap.go  DLL   derive the nibble permutation
//   -4   capture.go    DLL   dump the memory the stage routines read
//   -5   bla.go        BLA   carve the CHAI chain and the four key components
//   -6   derive.go     BLA   decrypt the signing key
//   -7   derive.go     BLA   derive the encryption key
//
// THE SPLIT IS A BUILD-TAG SPLIT, NOT A DIRECTORY SPLIT. Every file that touches the DLL
// carries //go:build windows, so on any other platform those files are not compiled and the
// four DLL steps are stubs that say so. Nothing in the DLL half reads the sample, and nothing
// in the sample half reads the DLL.
package main

import (
   "encoding/hex"
   "flag"
   "fmt"
   "os"
   "path/filepath"
   "strings"
   "time"
)

// outDir is the one directory the pipeline uses: the sample it reads and every file it writes.
const outDir = "testdata"

var (
   corePath = dataFile("msprcore.bla")

   // --- DLL phase -------------------------------------------------------
   prsubsPath  = dataFile("prsubs.json")
   scanLogPath = dataFile("findprsub.txt")
   imgPath     = dataFile("wbtool_img.bin")
   imgLogPath  = dataFile("decrypt_img.txt")
   profilePath = dataFile("dllprof.json")
   mapLogPath  = dataFile("derive_map.txt")

   // --- the -4 capture ---------------------------------------------------
   memPath        = dataFile("mem.bin")
   memMapPath     = dataFile("mem.json")
   captureLogPath = dataFile("capture.txt")

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

// dataFile returns the path inside outDir for a pipeline file.
func dataFile(name string) string { return filepath.Join(outDir, name) }

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

func hexOf(b []byte) string { return hex.EncodeToString(b) }

func main() {
   // A child is this binary re-executed with its mode in the environment and no arguments.
   // Checked before the FlagSet exists. On a platform without the DLL half this is a stub.
   if ok, err := childMode(); ok {
      if err != nil {
         fmt.Fprintf(os.Stderr, "prkf: %v\n", err)
         os.Exit(2)
      }
      return
   }

   // Declared and dispatched in step order, so neither can drift out of sequence.
   var (
      doFind    = flag.Bool("1", false, "DLL:  locate the signing-key routine")
      doImg     = flag.Bool("2", false, "DLL:  decrypt the Warbird image")
      doMap     = flag.Bool("3", false, "DLL:  derive the nibble permutation")
      doCap     = flag.Bool("4", false, "DLL:  dump the memory the stage routines read")
      doExtract = flag.Bool("5", false, "BLA:  carve the CHAI chain and the four key components")
      doDecrypt = flag.Bool("6", false, "BLA:  decrypt the signing key")
      doPlain   = flag.Bool("7", false, "BLA:  derive the encryption key")
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
   if *doCap {
      n++
      run = cmdCapture
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
      run = cmdDerive
   }

   if n == 0 {
      flag.Usage()
      os.Exit(2)
   }
   if n > 1 {
      fmt.Fprintln(os.Stderr, "prkf: select exactly one step")
      os.Exit(2)
   }

   if err := os.MkdirAll(outDir, 0o755); err != nil {
      fmt.Fprintf(os.Stderr, "prkf: %v\n", err)
      os.Exit(1)
   }

   // The elapsed line cannot be a deferred timer inside the step: main exits with the step's
   // code, which unwinds no frames.
   t0 := time.Now()
   code := run()
   fmt.Printf("elapsed %s\n", time.Since(t0).Round(time.Millisecond))
   os.Exit(code)
}

// ------------------------------------------------------------------- the step log

// stepLog is the log -2, -3, -4 and -7 keep: every line goes to the terminal as it is produced
// and to the step's file when the step ends, so no return path can leave the file unwritten.
// -1 does not use it: its log must be on disk before the next statement runs, because it is the
// only evidence a stalled scan leaves behind.
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
