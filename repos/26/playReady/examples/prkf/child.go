// child.go begin
//go:build windows

// Every body this binary re-executes, and the process plumbing they share.
//
//   -6's trials      dpWorkerP1, dpWorkerP2
//   -3's sweep       dmWorker
//   trial prep       pfImage, pfPrep, apply
//   spawn helpers    runCollect, probeBatch, dmSweep
//
// No goroutines, channels or mutexes anywhere in this program. Speed comes from
// doing less work per child: the descriptor census is cached in the profile by -2,
// so a child reads the image and patches a few dozen coalesced runs instead of
// hashing several gigabytes.
//
// # WHY A CHILD IS A SEPARATE PROCESS
//
// A fault in a descriptor's code is a Windows SEH exception raised inside the DLL,
// not a Go panic. recover() never runs and the whole process dies, so one child per
// candidate confines a fault to that candidate. Across 981 arbitrary code blobs that
// is the normal case, not an edge case.
//
// # WHAT A TRIAL REPORTS
//
// op=3 gets a 0x20-byte key and two 0x20-byte buffers, and a routine may write to
// either or both. Nothing states which, so every row carries BOTH buffers and the
// parent decides. Row format, both phases:
//
//   RES <i> <half> <a> <b>             two 0x20-byte buffers, hex
//   RES <i> <half> REJECT rc=.. st=..  the routine refused
//
// # THE -3 SWEEP CHILD
//
// -3's child is a different shape: one image patch, then every requested family,
// and a table of rows rather than one verdict. It lives here with the trial
// children because it shares the prep and the spawn helpers; its driver-side
// parser is dmSweep below.
//
// # EXIT CODES
//
// Nothing here calls os.Exit. Children return their code: 0 after their rows, 2 for
// a bad command line, 4 when the module cannot be loaded, 5 on bad input or a
// recovered panic, 6 when no fault handler could be installed.
package main

import (
   "bufio"
   "bytes"
   "context"
   "encoding/binary"
   "encoding/hex"
   "encoding/json"
   "fmt"
   "os"
   "os/exec"
   "path/filepath"
   "strconv"
   "strings"
   "time"
   "unsafe"
)

// ------------------------------------------------------- the -3 sweep child

// dmCLEN is one full bijection set: 64 blocks of 16 bytes, 0x400 in all. It is read
// by both the scan (nibblemap.go) and the patch, so it lives at package scope.
const dmCLEN = 0x400

var (
   // Static, never-moved scratch handed to native code.
   dmST  [0x40]byte
   dmOUT [0x100]byte
   dmKB  [0x48]byte
   dmARG [0x40]byte
   dmCB  []byte
)

// selfPath and selfErr are resolved once at init: three drivers spawn children of
// themselves and each needs the same answer.
var selfPath, selfErr = os.Executable()

// dmCall runs the consumer on one blob with the given 0x41-byte key and returns
// (ntstatus, status dword, 0x20-byte output). It is the one place the consumer's
// argument block is written:
//
//   +0x00  op = 3
//   +0x08  descriptor address
//   +0x10  -> status dword
//   +0x18  u32 0
//   +0x1C  -> key       (unaligned: a uintptr, like wbArgs.Out)
//   +0x24  u32 key size = 0x41
//   +0x28  -> blob
//   +0x30  -> output
//
// The results are copied out because dmST and dmOUT are reused by the next call.
func dmCall(base uintptr, desc uint32, prv, blob []byte) (uint32, []byte, []byte) {
   clear(dmST[:])
   clear(dmOUT[:])
   copy(dmKB[:], prv)
   dmCB = append(dmCB[:0], blob...)
   a := dmARG[:0x38]
   binary.LittleEndian.PutUint64(a[0x00:], 3)
   binary.LittleEndian.PutUint64(a[0x08:], uint64(base)+uint64(desc))
   binary.LittleEndian.PutUint64(a[0x10:], uint64(uintptr(unsafe.Pointer(&dmST[0]))))
   binary.LittleEndian.PutUint32(a[0x18:], 0)
   binary.LittleEndian.PutUint64(a[0x1C:], uint64(uintptr(unsafe.Pointer(&dmKB[0]))))
   binary.LittleEndian.PutUint32(a[0x24:], 0x41)
   binary.LittleEndian.PutUint64(a[0x28:], uint64(uintptr(unsafe.Pointer(&dmCB[0]))))
   binary.LittleEndian.PutUint64(a[0x30:], uint64(uintptr(unsafe.Pointer(&dmOUT[0]))))
   r, _, _ := wbNtQuery.Call(0xB9, uintptr(unsafe.Pointer(&a[0])), 0x38, 0)
   return uint32(r), append([]byte(nil), dmST[:4]...), append([]byte(nil), dmOUT[:0x20]...)
}

// dmLoadFail prints the LOADFAIL line the parent parses and yields exit code 4.
func dmLoadFail(f string, a ...any) int {
   fmt.Printf("LOADFAIL "+f+"\n", a...)
   return 4
}

// dmOut validates the field a child prints for one result: exactly 32 bytes of hex.
// Checking here rather than at the point of use means a format regression is
// reported against the row that caused it.
func dmOut(s string) (string, bool) {
   if len(s) != 0x40 {
      return "", false
   }
   if _, err := hex.DecodeString(s); err != nil {
      return "", false
   }
   return s, true
}

// dmPrv is a synthetic 0x41-byte key component. Deterministic and free of structure
// the routine could special-case: the first 0x40 bytes are a fixed non-repeating
// pattern, and byte 0x40 - the family selector - is the family.
//
// Only -3 uses it. -6 drives the real key, because the stage routines reject
// material that is not real; forcing the table here collapses whatever this key
// derives, so its bytes cannot matter.
func dmPrv(family int) []byte {
   p := make([]byte, 0x41)
   for i := 0; i < 0x40; i++ {
      p[i] = byte(i*37 + 0x5A)
   }
   p[0x40] = byte(family)
   return p
}

// dmWorker is the sweep child. One image patch, then every family: find the live
// set with one licence, sweep it with fifteen.
func dmWorker(descArg, famsArg, setsArg string) int {
   if descArg == "" || famsArg == "" || setsArg == "" {
      fmt.Fprintln(os.Stderr, "usage: prkf -3 sweep <descRVA> <families> <sets>")
      return 2
   }
   desc, err := strconv.ParseUint(descArg, 0, 32)
   if err != nil {
      return dmLoadFail("bad descriptor %q", descArg)
   }
   var fams []int
   for _, x := range strings.Split(famsArg, ",") {
      n, err := strconv.Atoi(x)
      if err != nil || n < 0 || n > 2 {
         return dmLoadFail("bad family %q", x)
      }
      fams = append(fams, n)
   }
   var sets []uint32
   for _, x := range strings.Split(setsArg, ",") {
      n, err := strconv.ParseUint(x, 0, 32)
      if err != nil {
         return dmLoadFail("bad set %q", x)
      }
      sets = append(sets, uint32(n))
   }
   if len(fams) == 0 || len(sets) == 0 {
      return dmLoadFail("empty family or set list")
   }

   // Every blob is read before the image is touched, so a missing licence fails in
   // milliseconds instead of after the span patch.
   blobs := make(map[int][]byte, 15)
   for nn := 1; nn <= 15; nn++ {
      b, err := os.ReadFile(filepath.Join(oracleDir, fmt.Sprintf("lic_%02x.blob", nn)))
      if err != nil {
         return dmLoadFail("licence %02x: %v", nn, err)
      }
      blobs[nn] = b
   }

   pi, err := pfPrep()
   if err != nil {
      return dmLoadFail("%v", err)
   }
   base, err := loadWarbird()
   if err != nil {
      return dmLoadFail("%v", err)
   }

   patched, skipped := pi.apply(base)
   fmt.Printf("PATCHED %d skipped %d\n", patched, skipped)

   // A false return means the child runs unprotected: a fault then kills it with no
   // FAULT line, and the driver reads that as missing rows.
   if !wbVEH(base, func(s string) {
      fmt.Println(s)
   }) {
      return dmLoadFail("AddVectoredExceptionHandler returned NULL")
   }

   // A failed patch does not merely skip work: the forced nibble is not forced, so
   // every row for that set is garbage. It is fatal.
   force := func(rva uint32, v byte) error {
      if !wbPatch(base, rva, bytes.Repeat([]byte{v}, dmCLEN)) {
         return fmt.Errorf("patch set 0x%x: VirtualProtect failed", rva)
      }
      return nil
   }
   readSet := func(rva uint32) []byte {
      o := make([]byte, dmCLEN)
      copy(o, unsafe.Slice((*byte)(wbMemAt(base+uintptr(rva))), dmCLEN))
      return o
   }

   for _, f := range fams {
      prv := dmPrv(f)

      // ---- phase 1: which set does this family read? ----------------------
      // One licence is enough: forcing 16 different nibbles through a table the
      // routine actually reads gives 16 different scalars, hence 16 different
      // outputs. A set it never reads gives the same output 16 times.
      liveIdx, nLive := -1, 0
      for i, srva := range sets {
         orig := readSet(srva)
         seen := map[string]bool{}
         ok := true
         for mm := 0; mm < 16; mm++ {
            if err := force(srva, byte(mm)); err != nil {
               return dmLoadFail("%v", err)
            }
            rc, sd, res := dmCall(base, uint32(desc), prv, blobs[1])
            if !wbPatch(base, srva, orig) {
               return dmLoadFail("restore set 0x%x: VirtualProtect failed", srva)
            }
            if rc != 0 || !statusOK(sd) {
               ok = false
               break
            }
            seen[hex.EncodeToString(res)] = true
         }
         d := len(seen)
         if !ok {
            d = 0
         }
         fmt.Printf("PROBE %d %d %d\n", f, i, d)
         if d == 16 {
            nLive++
            if liveIdx < 0 {
               liveIdx = i
            }
         }
      }
      if nLive != 1 {
         fmt.Printf("NOLIVE %d %d\n", f, nLive)
         continue
      }

      srva := sets[liveIdx]
      fmt.Printf("LIVE %d %d 0x%x\n", f, liveIdx, srva)

      // ---- phase 2: the full permutation ---------------------------------
      // Forced nibble outer, licence inner: one protection flip per forced value
      // instead of one per call.
      orig := readSet(srva)
      for mm := 0; mm < 16; mm++ {
         if err := force(srva, byte(mm)); err != nil {
            return dmLoadFail("%v", err)
         }
         for nn := 1; nn <= 15; nn++ {
            rc, sd, res := dmCall(base, uint32(desc), prv, blobs[nn])
            fmt.Printf("OUT %d %02x %02x rc=0x%08x st=%x %x\n", f, nn, mm, rc, sd, res)
         }
         if !wbPatch(base, srva, orig) {
            return dmLoadFail("restore set 0x%x: VirtualProtect failed", srva)
         }
      }
   }
   return 0
}

// dpHalf returns one 0x20-byte half of the key component. Byte 0x40 is the family
// selector and is never handed to a stage.
func dpHalf(prv []byte, h int) []byte {
   if h == 1 {
      return prv[0x20:0x40]
   }
   return prv[0:0x20]
}

// dpOp3 issues one WbHeapExecuteCall. It returns a closure over `base`, because a
// plain function would need nine parameters to say the same thing.
//
// It is not newWbArgs: the trial path passes a variable args length and writes a
// second size dword at +0x2C, which is wbArgs's blank padding and therefore
// unaddressable from Go.
//
// No runtime.KeepAlive is needed: syscall.(*LazyProc).Call is declared
// //go:uintptrescapes, so the compiler treats every converted pointer here as
// escaping for the duration of the call.
func dpOp3(base uintptr) func(descRVA, ln uint32, status, kb, out []byte, size2 *uint32) uint32 {
   return func(descRVA, ln uint32, status, kb, out []byte, size2 *uint32) uint32 {
      var a [0x40]byte
      binary.LittleEndian.PutUint64(a[0x00:], 3)
      binary.LittleEndian.PutUint64(a[0x08:], uint64(base)+uint64(descRVA))
      binary.LittleEndian.PutUint64(a[0x10:], uint64(uintptr(unsafe.Pointer(&status[0]))))
      binary.LittleEndian.PutUint64(a[0x18:], uint64(uintptr(unsafe.Pointer(&kb[0]))))
      binary.LittleEndian.PutUint32(a[0x20:], 0x20)
      binary.LittleEndian.PutUint64(a[0x24:], uint64(uintptr(unsafe.Pointer(&out[0]))))
      if size2 != nil {
         binary.LittleEndian.PutUint32(a[0x2C:], *size2)
      }
      r, _, _ := wbNtQuery.Call(0xB9, uintptr(unsafe.Pointer(&a[0])), uintptr(ln), 0)
      return uint32(r)
   }
}

// dpPrepChild loads what a trial needs and patches the image. It is the one place a
// child pays its fixed cost, so both trial bodies call it and nothing else does.
func dpPrepChild() (op3 func(uint32, uint32, []byte, []byte, []byte, *uint32) uint32,
   prv []byte, code int, err error) {

   pi, err := pfPrep()
   if err != nil {
      return nil, nil, 5, err
   }
   if prv, err = dpPrv(); err != nil {
      return nil, nil, 5, err
   }
   base, err := loadWarbird()
   if err != nil {
      return nil, nil, 4, err
   }
   pi.apply(base)

   if !wbVEH(base, func(s string) { fmt.Println(s) }) {
      return nil, nil, 6, fmt.Errorf("AddVectoredExceptionHandler returned NULL")
   }
   return dpOp3(base), prv, 0, nil
}

// ------------------------------------------------------- the -6 trial child

// dpPrv reads the sample's 0x41-byte key component. Every trial drives it: the
// stage routines reject key material that is not real, which is why a synthetic key
// made the search unfindable.
func dpPrv() ([]byte, error) {
   prv, err := os.ReadFile(encPrvPath)
   if err != nil {
      return nil, fmt.Errorf("missing %s - run prkf -4 first", encPrvPath)
   }
   if len(prv) != 0x41 {
      return nil, fmt.Errorf("%s is %d bytes, expected 0x41 (65)", encPrvPath, len(prv))
   }
   return prv, nil
}

// dpStage1 is the stage-1 call: a 0x20-byte key half in the key buffer, 0x2C bytes
// of arguments, no second size. Both buffers are returned, because which one the
// routine treats as its output is not established.
func dpStage1(op3 func(uint32, uint32, []byte, []byte, []byte, *uint32) uint32,
   desc uint32, key []byte) (out, kb []byte, rc uint32, st []byte) {

   st1 := make([]byte, 0x40)
   b1 := make([]byte, 0x40)
   b2 := make([]byte, 0x40)
   copy(b1, key)

   rc = op3(desc, 0x2C, st1, b1, b2, nil)
   return b2[:0x20], b1[:0x20], rc, st1[:4]
}

// dpStage2 runs one stage-2 trial: the OBF in the key buffer, a 0x20-byte key half
// in the output buffer, 0x30 bytes of arguments with a second size dword.
func dpStage2(op3 func(uint32, uint32, []byte, []byte, []byte, *uint32) uint32,
   desc uint32, obf, key []byte) (kb, out []byte, rc uint32, st []byte) {

   st2 := make([]byte, 0x40)
   b1 := make([]byte, 0x40)
   b2 := make([]byte, 0x40)
   copy(b1, obf)
   copy(b2, key)

   sz := uint32(0x20)
   rc = op3(desc, 0x30, st2, b1, b2, &sz)
   return b1[:0x20], b2[:0x20], rc, st2[:4]
}

// dpWorkerP1 is the stage-1 probe: every candidate, both key halves, both buffers.
//
// Reporting both buffers is what makes the search exhaustive rather than a guess:
// the routine is handed a 0x20-byte key and two 0x20-byte buffers, and nothing
// establishes which one it treats as output.
func dpWorkerP1(descs []uint32) (code int) {
   say := func(f string, a ...any) { fmt.Printf("S1 "+f+"\n", a...) }
   defer func() {
      if r := recover(); r != nil {
         say("ERR %v", r)
         code = 5
      }
   }()

   op3, prv, code, err := dpPrepChild()
   if err != nil {
      say("ERR %v", err)
      return code
   }

   for i, d := range descs {
      for h := 0; h < 2; h++ {
         out, kb, rc, sd := dpStage1(op3, d, dpHalf(prv, h))
         if rc != 0 || !statusOK(sd) {
            say("RES %d %d REJECT rc=0x%08x st=%s", i, h, rc, hex.EncodeToString(sd))
            continue
         }
         say("RES %d %d %s %s", i, h, hex.EncodeToString(out), hex.EncodeToString(kb))
      }
   }
   return 0
}

// dpWorkerP2 is the stage-2 probe: every (candidate, OBF, key half) from `start`
// onwards. The index is flattened as (di*len(obfs)+oi)*2+h, so a resume point is one
// integer.
func dpWorkerP2(start int, obfs []string, descs []uint32) (code int) {
   say := func(f string, a ...any) { fmt.Printf("MX "+f+"\n", a...) }
   defer func() {
      if r := recover(); r != nil {
         say("ERR %v", r)
         code = 5
      }
   }()

   op3, prv, code, err := dpPrepChild()
   if err != nil {
      say("ERR %v", err)
      return code
   }

   n := len(obfs)
   for idx := start; idx < len(descs)*n*2; idx++ {
      di := idx / (n * 2)
      oi, h := (idx%(n*2))/2, idx%2
      obf, err := hex.DecodeString(obfs[oi])
      if err != nil || len(obf) != 0x20 {
         say("ERR bad obf %q", obfs[oi])
         return 5
      }
      kb, out, rc, st := dpStage2(op3, descs[di], obf, dpHalf(prv, h))
      if rc != 0 || !statusOK(st) {
         say("RES %d %d REJECT rc=0x%08x st=%s", idx, h, rc, hex.EncodeToString(st))
         continue
      }
      say("RES %d %d %s %s", idx, h, hex.EncodeToString(kb), hex.EncodeToString(out))
   }
   return 0
}

// probeBatch re-executes this binary as a probe child for a list of descriptors and
// returns the RESULT line each one produced, keyed by descriptor VA. A descriptor
// with no line faulted or was never reached, and the caller retries it alone.
//
// stderr is streamed into w as it arrives rather than buffered: a child that hangs
// never exits, and the last trace line is the only evidence of where.
func probeBatch(descs []imgDesc, w func(string)) map[uint32]string {
   out := map[uint32]string{}
   if len(descs) == 0 {
      return out
   }
   if selfErr != nil {
      w(fmt.Sprintf("  spawn: %v", selfErr))
      return out
   }

   vas := make([]string, len(descs))
   for i, d := range descs {
      vas[i] = fmt.Sprintf("%#x", d.descVA)
   }
   cmd := exec.Command(selfPath)
   cmd.Env = append(os.Environ(), probeEnv+"="+strings.Join(vas, ","))

   var stdout bytes.Buffer
   cmd.Stdout = &stdout

   er, err := cmd.StderrPipe()
   if err != nil {
      w(fmt.Sprintf("  stderr pipe: %v", err))
      return out
   }
   if err := cmd.Start(); err != nil {
      w(fmt.Sprintf("  start: %v", err))
      return out
   }

   sc := bufio.NewScanner(er)
   sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
   for sc.Scan() {
      w("  " + sc.Text())
   }
   // sc.Err is the only signal that the trace ended early. Dropped, it would make a
   // truncated trace indistinguishable from a complete one.
   if serr := sc.Err(); serr != nil {
      w(fmt.Sprintf("  TRACE TRUNCATED: %v", serr))
   }

   // Reading to EOF before Wait is the documented pattern: Wait closes the pipe, so
   // every trace line is in the log before the rows are read.
   if err := cmd.Wait(); err != nil {
      w(fmt.Sprintf("  exit: %v", err))
   }

   for _, l := range strings.Split(stdout.String(), "\n") {
      l = strings.TrimRight(l, "\r")
      if !strings.HasPrefix(l, "RESULT ") {
         continue
      }
      f := strings.Fields(l)
      if len(f) < 2 {
         continue
      }
      if va, err := strconv.ParseUint(f[1], 0, 32); err == nil {
         out[uint32(va)] = l
      }
   }
   return out
}

// dmFam is one family's rows from a sweep child. nLive is 1 when exactly one set
// answered 16 distinct outputs; liveRVA is that set. The LIVE row's set index is
// deliberately not kept: it names a position in the driver's own set list, which is
// in derive_map.txt, so it is a label for a human rather than a value for code.
type dmFam struct {
   nLive   int
   liveRVA uint32
   outs    map[int]map[int]string // licence -> forced nibble -> hex
}

// dmResult is one sweep child, parsed.
type dmResult struct {
   fams     map[int]*dmFam
   meta     []string
   fault    string
   loadfail string
   rc       int
}

// dmSweep spawns one sweep child for the given families and parses its rows.
func dmSweep(descRVA uint32, fams []int, sets []uint32) dmResult {
   fs := make([]string, len(fams))
   for i, x := range fams {
      fs[i] = strconv.Itoa(x)
   }
   rs := make([]string, len(sets))
   for i, x := range sets {
      rs[i] = fmt.Sprintf("0x%x", x)
   }
   p := runCollect([]string{
      "-3", "sweep",
      fmt.Sprintf("0x%x", descRVA),
      strings.Join(fs, ","),
      strings.Join(rs, ","),
   }, 30*time.Minute)

   r := dmResult{fams: map[int]*dmFam{}, rc: p.rc}
   if p.err != nil {
      r.loadfail = "LOADFAIL " + p.err.Error()
      return r
   }

   fam := func(i int) *dmFam {
      if r.fams[i] == nil {
         r.fams[i] = &dmFam{outs: map[int]map[int]string{}}
      }
      return r.fams[i]
   }

   for _, ln := range strings.Split(string(p.stdout), "\n") {
      f := strings.Fields(ln)
      if len(f) < 2 {
         continue
      }
      switch f[0] {
      case "PATCHED":
         r.meta = append(r.meta, ln)
      case "LOADFAIL":
         r.loadfail = ln
      case "FAULT":
         r.fault = ln
      case "LIVE":
         if len(f) < 4 {
            r.loadfail = "LOADFAIL malformed LIVE row: " + ln
            return r
         }
         v, e1 := strconv.Atoi(f[1])
         _, e2 := strconv.Atoi(f[2]) // set index: validated, not retained
         rva, e3 := strconv.ParseUint(f[3], 0, 32)
         if e1 != nil || e2 != nil || e3 != nil {
            r.loadfail = "LOADFAIL malformed LIVE row: " + ln
            return r
         }
         fm := fam(v)
         fm.liveRVA, fm.nLive = uint32(rva), 1
      case "NOLIVE":
         if len(f) < 3 {
            r.loadfail = "LOADFAIL malformed NOLIVE row: " + ln
            return r
         }
         v, e1 := strconv.Atoi(f[1])
         n, e2 := strconv.Atoi(f[2])
         if e1 != nil || e2 != nil {
            r.loadfail = "LOADFAIL malformed NOLIVE row: " + ln
            return r
         }
         fm := fam(v)
         fm.nLive, fm.liveRVA = n, 0
      case "OUT":
         if len(f) < 6 {
            r.loadfail = "LOADFAIL malformed OUT row: " + ln
            return r
         }
         v, e1 := strconv.Atoi(f[1])
         nn, e2 := strconv.ParseInt(f[2], 16, 64)
         mm, e3 := strconv.ParseInt(f[3], 16, 64)
         if e1 != nil || e2 != nil || e3 != nil {
            r.loadfail = "LOADFAIL malformed OUT row: " + ln
            return r
         }
         val, ok := dmOut(f[len(f)-1])
         if !ok {
            r.loadfail = "LOADFAIL OUT value is not 32 hex bytes: " + ln
            return r
         }
         fm := fam(v)
         if fm.outs[int(nn)] == nil {
            fm.outs[int(nn)] = map[int]string{}
         }
         fm.outs[int(nn)][int(mm)] = val
      }
   }
   return r
}

// dmSweepAll is dmSweep plus the fault fallback: one child covers all families, so
// a fault costs every family at once. Re-running one family at a time salvages the
// ones that did not fault, and costs nothing when the batch succeeds.
func dmSweepAll(descRVA uint32, fams []int, sets []uint32, logf func(string, ...any)) dmResult {
   r := dmSweep(descRVA, fams, sets)
   if r.loadfail != "" || len(fams) <= 1 {
      return r
   }
   if r.fault == "" && r.rc == 0 {
      return r
   }

   logf("  batch child stopped early - retrying one family at a time")
   for _, f := range fams {
      if fm, ok := r.fams[f]; ok && (fm.nLive != 1 || len(fm.outs) == 15) {
         continue
      }
      one := dmSweep(descRVA, []int{f}, sets)
      if one.loadfail != "" {
         r.loadfail = one.loadfail
         return r
      }
      if fm, ok := one.fams[f]; ok {
         r.fams[f] = fm
      }
   }
   r.fault = ""
   return r
}

// ------------------------------------------------------------- the trial prep

// pfImage is everything a trial child or a -3 sweep needs: the decrypted image, the
// census, and the patch plan. It deliberately does NOT include the module: a child
// used to read the DLL and re-run scanDescs, which hashes several gigabytes, and
// that was the cost of every child and therefore of every fault.
type pfImage struct {
   sha    string
   size   uint32
   img    []byte
   heaps  []imgDesc
   spans  []imgSpan
   merged []imgInterval
}

// pfPrep loads the census and the image. The size check is what proves the image on
// disk came from this build: the image's own hash changes every run, because
// LoadLibraryW bakes the load base into relocated fields, but SizeOfImage is a
// per-build constant.
func pfPrep() (*pfImage, error) {
   raw, err := os.ReadFile(profilePath)
   if err != nil {
      return nil, fmt.Errorf("no %s - run prkf -2 first", profilePath)
   }
   var p dllProfile
   if err := json.Unmarshal(raw, &p); err != nil {
      return nil, fmt.Errorf("%s: %v", profilePath, err)
   }
   if p.Census == nil || len(p.Census.Heaps) == 0 {
      return nil, fmt.Errorf("%s has no census - re-run prkf -2", profilePath)
   }

   pi := &pfImage{sha: p.DLLSHA256, size: p.SizeOfImage}
   if pi.img, err = os.ReadFile(imgPath); err != nil {
      return nil, err
   }
   if uint32(len(pi.img)) != pi.size {
      return nil, fmt.Errorf("%s is %d bytes but this build's SizeOfImage is 0x%x - run prkf -2",
         imgPath, len(pi.img), pi.size)
   }

   for _, h := range p.Census.Heaps {
      pi.heaps = append(pi.heaps, imgDesc{va: h[0], descVA: h[1], rva: h[2], ln: h[3]})
   }
   for _, s := range p.Census.Spans {
      pi.spans = append(pi.spans, imgSpan{rva: s[0], size: s[1]})
   }
   pi.merged = mergeIntervals(heapIntervals(pi.heaps))
   return pi, nil
}

// apply patches the segment plaintext into the loaded image, carving around the
// heap-exec blocks the kernel decrypts itself.
//
// Every span is written, not just the ones that differ from the file: writing the
// image's own bytes over an unencrypted span is a no-op, and skipping the comparison
// is what lets a child avoid reading the module at all. The runs are coalesced
// first, so the protection flips number in the dozens.
func (p *pfImage) apply(base uintptr) (patched, skipped int) {
   var runs []imgRun
   for _, s := range p.spans {
      if uint64(s.rva)+uint64(s.size) > uint64(len(p.img)) {
         continue
      }
      r := carveRuns(p.merged, s.rva, s.size)
      if len(r) == 0 {
         skipped++
         continue
      }
      runs = append(runs, r...)
   }

   for _, r := range coalesceRuns(runs) {
      if wbPatch(base, r.start, p.img[r.start:r.start+r.length]) {
         patched++
      } else {
         skipped++
      }
   }
   return patched, skipped
}

// ------------------------------------------------------------ spawn helpers

// procOut is one collected child run. rc is -1 when the child produced no verdict:
// it was killed by the deadline, or it could not be started at all, which is the
// one case err reports.
type procOut struct {
   stdout []byte
   rc     int
   err    error
}

// runCollect spawns this binary with args under a deadline and returns its stdout.
// A non-zero exit is reported as rc, not as an error: every child signals failure
// that way on purpose, and the caller parses stdout for the reason. err is non-nil
// only when the process could not be started.
func runCollect(args []string, timeout time.Duration) procOut {
   if selfErr != nil {
      return procOut{rc: -1, err: selfErr}
   }
   ctx, cancel := context.WithTimeout(context.Background(), timeout)
   defer cancel()

   cmd := exec.CommandContext(ctx, selfPath, args...)
   var so bytes.Buffer
   cmd.Stdout = &so
   runErr := cmd.Run()

   p := procOut{stdout: so.Bytes(), rc: -1}
   if ctx.Err() != nil {
      return p // deadline hit: no verdict, and not a start failure either
   }
   switch e := runErr.(type) {
   case nil:
      p.rc = 0
   case *exec.ExitError:
      p.rc = e.ExitCode()
   default:
      p.err = runErr
   }
   return p
}

// child.go end
