// child.go begin
//go:build windows

// Every body this binary re-executes, and the process plumbing they share.
//
//   -6's trials      dpWorkerP1, dpWorkerP2
//   -3's sweep       dmWorker
//   trial prep       pfImage, pfPrep, apply
//   spawn helpers    runCollect, probeBatch, dmSweep
//
// A CHILD IS IDENTIFIED BY ITS ENVIRONMENT, NOT BY ITS ARGUMENTS. Every body here is
// selected by one environment variable and is passed no arguments at all, so no child
// mode can appear in `prkf -h` and every step has an empty command line.
//
// THE PAYLOAD IS ONE JSON OBJECT. It was three ';'/',' mini-DSLs, each with its own
// parser, its own error text, and no way to tell an empty list from a malformed one.
// childSpec is decoded once in childMode, which is therefore the only validator, and
// every spawn site passes a struct rather than formatting a string the child must then
// re-parse.
//
// WHY A CHILD IS A SEPARATE PROCESS: a fault in a descriptor's code is a Windows SEH
// exception raised inside the DLL, not a Go panic. recover() never runs and the whole
// process dies, so one child per candidate confines a fault to that candidate.
//
// WHAT A TRIAL REPORTS: op=3 gets a 0x20-byte key and two 0x20-byte buffers, and a
// routine may write to either or both. Nothing states which, so every row carries BOTH
// buffers and the parent decides. Row format, both phases:
//
//   RES <i> <half> <a> <b>             two 0x20-byte buffers, hex
//   RES <i> <half> REJECT rc=.. st=..  the routine refused
//
// EXIT CODES: nothing here calls os.Exit. Children return their code: 0 after their
// rows, 2 for a bad payload, 4 when the module cannot be loaded, 5 on bad input or a
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

// childEnv is the one variable a child is identified by. Its value is a JSON
// childSpec; nothing else about the process differs from its parent.
const childEnv = "PRKF_CHILD"

// ------------------------------------------------------- the -3 sweep child

// dmCLEN is one full bijection set: 64 blocks of 16 bytes, 0x400 in all. It is read by
// both the scan (nibblemap.go) and the patch, so it lives at package scope.
const dmCLEN = 0x400

// Static, never-moved scratch handed to native code.
var (
   dmST  [0x40]byte
   dmOUT [0x100]byte
   dmKB  [0x48]byte
   dmARG [0x40]byte
   dmCB  []byte
)

// selfPath and selfErr are resolved once at init: three drivers spawn children of
// themselves and each needs the same answer.
var selfPath, selfErr = os.Executable()

// childEnvFor renders spec as the one NAME=VALUE entry a spawn site passes.
func childEnvFor(spec childSpec) (string, error) {
   b, err := json.Marshal(spec)
   if err != nil {
      return "", fmt.Errorf("%s: %w", childEnv, err)
   }
   return childEnv + "=" + string(b), nil
}

// childEnvList is os.Environ with any inherited childEnv removed. syscall.Getenv on
// Windows returns the FIRST match, so appending a payload to an environment that
// already holds one shadows the new spec and the child silently repeats the old work.
func childEnvList(entry string) []string {
   env := os.Environ()
   out := make([]string, 0, len(env)+1)
   for _, e := range env {
      if !strings.HasPrefix(e, childEnv+"=") {
         out = append(out, e)
      }
   }
   return append(out, entry)
}

// childMode reports whether this process was started as one of the re-executed
// children, and runs it if so. Called from main before the FlagSet exists: a child
// passes no arguments, so there is nothing for the FlagSet to parse.
//
// It is also the ONLY place a child payload is validated. Each mode names exactly the
// fields it needs, so a malformed or half-populated spec fails here with one message
// rather than in whichever worker happened to trip over it.
//
// An error means the payload was malformed, which is a spawn bug rather than a data
// problem, so main exits 2 on it.
func childMode() (code int, ok bool, err error) {
   s := os.Getenv(childEnv)
   if s == "" {
      return 0, false, nil
   }

   var spec childSpec
   if err := json.Unmarshal([]byte(s), &spec); err != nil {
      return 0, true, fmt.Errorf("%s: %w", childEnv, err)
   }

   switch spec.Mode {
   case "probe":
      if len(spec.Descs) == 0 {
         return 0, true, fmt.Errorf("%s: probe with no descriptors", childEnv)
      }
      return runProbes(spec.Descs), true, nil

   case "sweep":
      // One descriptor, because a sweep drives one consumer. Families are indices into
      // dmFams, so the range is checked against it and not against a literal 2 that
      // could drift from the list.
      if len(spec.Descs) != 1 {
         return 0, true, fmt.Errorf("%s: sweep needs exactly one descriptor, got %d",
            childEnv, len(spec.Descs))
      }
      if len(spec.Fams) == 0 || len(spec.Sets) == 0 {
         return 0, true, fmt.Errorf("%s: sweep needs families and sets", childEnv)
      }
      for _, f := range spec.Fams {
         if f < 0 || f >= len(dmFams) {
            return 0, true, fmt.Errorf("%s: family %d is not one of %d",
               childEnv, f, len(dmFams))
         }
      }
      return dmWorker(spec.Descs[0], spec.Fams, spec.Sets), true, nil

   case "p1":
      if len(spec.Descs) == 0 {
         return 0, true, fmt.Errorf("%s: p1 with no descriptors", childEnv)
      }
      return dpWorkerP1(spec.Descs), true, nil

   case "p2":
      if len(spec.Descs) == 0 || len(spec.Obfs) == 0 {
         return 0, true, fmt.Errorf("%s: p2 needs descriptors and OBFs", childEnv)
      }
      if spec.Start < 0 {
         return 0, true, fmt.Errorf("%s: p2 start %d is negative", childEnv, spec.Start)
      }
      return dpWorkerP2(spec.Start, spec.Obfs, spec.Descs), true, nil
   }
   return 0, true, fmt.Errorf("%s: unknown mode %q", childEnv, spec.Mode)
}

// dmCall runs the consumer on one blob with the given 0x41-byte key and returns
// (ntstatus, status dword, 0x20-byte output). It is NOT op3Call: this consumer's
// routine takes a blob, so its argument block is a different shape.
//
//   +0x00  op = 3
//   +0x08  descriptor address
//   +0x10  -> status dword
//   +0x18  u32 0
//   +0x1C  -> key       (unaligned: a uintptr, like the output pointer below)
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
// Checking here rather than at the point of use means a format regression is reported
// against the row that caused it.
func dmOut(s string) (string, bool) {
   if len(s) != 0x40 {
      return "", false
   }
   if _, err := hex.DecodeString(s); err != nil {
      return "", false
   }
   return s, true
}

// dmPrv is a synthetic 0x41-byte key component. Deterministic and free of structure the
// routine could special-case: the first 0x40 bytes are a fixed non-repeating pattern,
// and byte 0x40 - the family selector - is the family.
//
// Only -3 uses it. -6 drives the real key, because the stage routines reject material
// that is not real; forcing the table here collapses whatever this key derives, so its
// bytes cannot matter.
func dmPrv(family int) []byte {
   p := make([]byte, 0x41)
   for i := 0; i < 0x40; i++ {
      p[i] = byte(i*37 + 0x5A)
   }
   p[0x40] = byte(family)
   return p
}

// dmWorker is the sweep child. One image patch, then every family: find the live set
// with one licence, sweep it with fifteen.
//
// Its arguments arrive decoded and already validated by childMode, so this body is the
// work and nothing else.
func dmWorker(desc uint32, fams []int, sets []uint32) int {
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
   if !wbVEH(base) {
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
      // One licence is enough: forcing 16 different nibbles through a table the routine
      // actually reads gives 16 different scalars, hence 16 different outputs. A set it
      // never reads gives the same output 16 times.
      liveIdx, nLive := -1, 0
      for i, srva := range sets {
         orig := readSet(srva)
         seen := map[string]bool{}
         ok := true
         for mm := 0; mm < 16; mm++ {
            if err := force(srva, byte(mm)); err != nil {
               return dmLoadFail("%v", err)
            }
            rc, sd, res := dmCall(base, desc, prv, blobs[1])
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
      // Forced nibble outer, licence inner: one protection flip per forced value instead
      // of one per call.
      orig := readSet(srva)
      for mm := 0; mm < 16; mm++ {
         if err := force(srva, byte(mm)); err != nil {
            return dmLoadFail("%v", err)
         }
         for nn := 1; nn <= 15; nn++ {
            rc, sd, res := dmCall(base, desc, prv, blobs[nn])
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

// ------------------------------------------------------- the -6 trial child

// dpPrv reads the sample's 0x41-byte key component. Every trial drives it: the stage
// routines reject key material that is not real, which is why a synthetic key made the
// search unfindable.
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

// dpTrial runs one op=3 trial. k1 goes in the key buffer, k2 in the output buffer, and
// ln / size2 are the only things that differ between the two stages: stage 1 is 0x2C
// bytes with no second size, stage 2 is 0x30 bytes with a 0x20 there.
//
// Both buffers come back because which one a routine treats as its output is not
// established; the caller picks with its recorded O index.
func dpTrial(op3 op3Func, desc, ln uint32, k1, k2 []byte, size2 *uint32) (kb, out []byte, rc uint32, st []byte) {
   sb := make([]byte, 0x40)
   b1 := make([]byte, 0x40)
   b2 := make([]byte, 0x40)
   copy(b1, k1)
   copy(b2, k2) // nil k2 leaves this zero-filled

   rc = op3(desc, ln, 0x20, sb, b1, b2, size2)
   return b1[:0x20], b2[:0x20], rc, sb[:4]
}

// dpWorkerP1 is the stage-1 probe: every candidate, both key halves, both buffers.
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
         kb, out, rc, sd := dpTrial(op3, d, 0x2C, dpHalf(prv, h), nil, nil)
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

   sz := uint32(0x20)
   n := len(obfs)
   for idx := start; idx < len(descs)*n*2; idx++ {
      di := idx / (n * 2)
      oi, h := (idx%(n*2))/2, idx%2
      obf, err := hex.DecodeString(obfs[oi])
      if err != nil || len(obf) != 0x20 {
         say("ERR bad obf %q", obfs[oi])
         return 5
      }
      kb, out, rc, st := dpTrial(op3, descs[di], 0x30, obf, dpHalf(prv, h), &sz)
      if rc != 0 || !statusOK(st) {
         say("RES %d %d REJECT rc=0x%08x st=%s", idx, h, rc, hex.EncodeToString(st))
         continue
      }
      say("RES %d %d %s %s", idx, h, hex.EncodeToString(kb), hex.EncodeToString(out))
   }
   return 0
}

// probeBatch re-executes this binary as a probe child for a list of descriptors and
// returns the RESULT line each one produced, keyed by descriptor VA. A descriptor with
// no line faulted or was never reached, and the caller recovers it.
//
// stderr is streamed into w as it arrives rather than buffered: a child that hangs never
// exits, and the last trace line is the only evidence of where.
func probeBatch(descs []imgDesc, w func(string)) map[uint32]string {
   out := map[uint32]string{}
   if len(descs) == 0 {
      return out
   }
   if selfErr != nil {
      w(fmt.Sprintf("  spawn: %v", selfErr))
      return out
   }

   vas := make([]uint32, len(descs))
   for i, d := range descs {
      vas[i] = d.descVA
   }
   entry, err := childEnvFor(childSpec{Mode: "probe", Descs: vas})
   if err != nil {
      w(fmt.Sprintf("  spawn: %v", err))
      return out
   }

   cmd := exec.Command(selfPath)
   cmd.Env = childEnvList(entry)

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

// dpPrepChild loads what a trial needs and patches the image. It is the one place a
// child pays its fixed cost, so both trial bodies call it and nothing else does.
func dpPrepChild() (op3 op3Func, prv []byte, code int, err error) {
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

   if !wbVEH(base) {
      return nil, nil, 6, fmt.Errorf("AddVectoredExceptionHandler returned NULL")
   }
   return op3Call(base), prv, 0, nil
}

// childSpec is a child's whole payload. Descs is per-mode: descriptor VAs for "probe",
// "p1" and "p2", and the single consumer descRVA for "sweep". The remaining fields are
// read by the one mode that uses them and ignored by the rest, so a mode's requirements
// are stated once, in childMode.
type childSpec struct {
   Mode  string   `json:"mode"`            // probe | sweep | p1 | p2
   Descs []uint32 `json:"descs,omitempty"` // probe, p1, p2; sweep uses the one element
   Fams  []int    `json:"fams,omitempty"`  // sweep
   Sets  []uint32 `json:"sets,omitempty"`  // sweep
   Obfs  []string `json:"obfs,omitempty"`  // p2
   Start int      `json:"start,omitempty"` // p2
}

// dmFam is one family's rows from a sweep child. nLive is 1 when exactly one set
// answered 16 distinct outputs; liveRVA is that set.
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
   p := runCollect(childSpec{
      Mode:  "sweep",
      Descs: []uint32{descRVA},
      Fams:  fams,
      Sets:  sets,
   }, 30*time.Minute)

   r := dmResult{fams: map[int]*dmFam{}, rc: p.rc}
   if p.err != nil {
      r.loadfail = "LOADFAIL " + p.err.Error()
      return r
   }
   bad := func(ln string) dmResult {
      r.loadfail = "LOADFAIL malformed row: " + ln
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
      case "PATCHED", "PROBE":
         // The only rows not consumed as results. PROBE is the per-set evidence behind
         // the live-set verdict, so it belongs in the log rather than being computed and
         // dropped.
         r.meta = append(r.meta, ln)

      case "LOADFAIL":
         r.loadfail = ln
      case "FAULT":
         r.fault = ln

      case "LIVE":
         if len(f) < 4 {
            return bad(ln)
         }
         v, e1 := strconv.Atoi(f[1])
         rva, e2 := strconv.ParseUint(f[3], 0, 32) // f[2] is the set index, not retained
         if e1 != nil || e2 != nil {
            return bad(ln)
         }
         fm := fam(v)
         fm.liveRVA, fm.nLive = uint32(rva), 1

      case "NOLIVE":
         if len(f) < 3 {
            return bad(ln)
         }
         v, e1 := strconv.Atoi(f[1])
         n, e2 := strconv.Atoi(f[2])
         if e1 != nil || e2 != nil {
            return bad(ln)
         }
         fm := fam(v)
         fm.nLive, fm.liveRVA = n, 0

      case "OUT":
         // OUT <family> <licence> <forced> rc=.. st=.. <value>
         if len(f) < 7 {
            return bad(ln)
         }
         v, e1 := strconv.Atoi(f[1])
         nn, e2 := strconv.ParseUint(f[2], 16, 8)
         mm, e3 := strconv.ParseUint(f[3], 16, 8)
         val, ok := dmOut(f[6])
         if e1 != nil || e2 != nil || e3 != nil || !ok {
            return bad(ln)
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

// dmSweepAll is dmSweep plus the fault fallback: one child covers all families, so a
// fault costs every family at once. Re-running one family at a time salvages the ones
// that did not fault, and costs nothing when the batch succeeds.
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
// census, the patch plan, and the profile those came from. It deliberately does NOT
// include the module: a child used to read the DLL and re-run scanDescs, which hashes
// several gigabytes.
//
// prof is the parse pfPrep already performed. Carrying it is what stops the BLA-phase
// steps reading and unmarshalling dllprof.json a second time just to reach Map and
// Stages.
type pfImage struct {
   sha    string
   size   uint32
   img    []byte
   heaps  []imgDesc
   spans  []imgRun
   merged []imgRun
   prof   *dllProfile
}

// pfPrep loads the census and the image. The size check is what proves the image on disk
// came from this build: the image's own hash changes every run, because LoadLibraryW
// bakes the load base into relocated fields, but SizeOfImage is a per-build constant.
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

   pi := &pfImage{sha: p.DLLSHA256, size: p.SizeOfImage, prof: &p}
   if pi.img, err = os.ReadFile(imgPath); err != nil {
      return nil, err
   }
   if uint32(len(pi.img)) != pi.size {
      return nil, fmt.Errorf("%s is %d bytes but this build's SizeOfImage is 0x%x - run prkf -2",
         imgPath, len(pi.img), pi.size)
   }

   for _, h := range p.Census.Heaps {
      d := imgDesc{va: h[0], descVA: h[1], rva: h[2], ln: h[3]}
      pi.heaps = append(pi.heaps, d)
      if d.ln != 0 {
         pi.merged = append(pi.merged, imgRun{d.rva, d.ln})
      }
   }
   for _, s := range p.Census.Spans {
      pi.spans = append(pi.spans, imgRun{s[0], s[1]})
   }
   pi.merged = mergeRuns(pi.merged)
   return pi, nil
}

// apply patches the segment plaintext into the loaded image, carving around the
// heap-exec blocks the kernel decrypts itself.
//
// Every span is written, not just the ones that differ from the file: writing the
// image's own bytes over an unencrypted span is a no-op, and skipping the comparison is
// what lets a child avoid reading the module at all. The runs are coalesced first, so
// the protection flips number in the dozens.
func (p *pfImage) apply(base uintptr) (patched, skipped int) {
   var runs []imgRun
   for _, s := range p.spans {
      if uint64(s.start)+uint64(s.length) > uint64(len(p.img)) {
         continue
      }
      r := carveRuns(p.merged, s.start, s.length)
      if len(r) == 0 {
         skipped++
         continue
      }
      runs = append(runs, r...)
   }

   for _, r := range mergeRuns(runs) {
      if wbPatch(base, r.start, p.img[r.start:r.start+r.length]) {
         patched++
      } else {
         skipped++
      }
   }
   return patched, skipped
}

// ------------------------------------------------------------ spawn helpers

// procOut is one collected child run. rc is -1 when the child produced no verdict: it
// was killed by the deadline, or it could not be started at all, which is the one case
// err reports.
type procOut struct {
   stdout []byte
   rc     int
   err    error
}

// runCollect spawns this binary as a child under a deadline and returns its stdout. The
// child is identified by env alone and is passed no arguments; spec is encoded here, so
// no caller ever formats a payload and no child ever re-parses a hand-built string.
//
// A non-zero exit is reported as rc, not as an error: every child signals failure that
// way on purpose, and the caller parses stdout for the reason. err is non-nil only when
// the process could not be started or the spec could not be encoded.
func runCollect(spec childSpec, timeout time.Duration) procOut {
   if selfErr != nil {
      return procOut{rc: -1, err: selfErr}
   }
   entry, err := childEnvFor(spec)
   if err != nil {
      return procOut{rc: -1, err: err}
   }

   ctx, cancel := context.WithTimeout(context.Background(), timeout)
   defer cancel()

   cmd := exec.CommandContext(ctx, selfPath)
   cmd.Env = childEnvList(entry)
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
