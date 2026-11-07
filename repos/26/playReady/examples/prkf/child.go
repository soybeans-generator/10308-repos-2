// child.go begin
//go:build windows

// The two bodies this binary re-executes, and the trace plumbing they share.
//
//   -2's descriptor probe   probeTarget, runOne, worker, emit, probe
//   -7's (s1, s2) trial     dpWorker
//
// Both take one candidate, run it in a fresh process, and print one terminal
// verdict line the parent turns into a result kind. -6's sweep child is a
// different shape - it prints a table of rows for one set - and lives with its
// driver in nibblemap.go.
//
// # WHY THE PROBE IS A SEPARATE PROCESS
//
// A fault in a descriptor's code is a Windows SEH exception raised inside the
// DLL, not a Go panic. The Go runtime only converts exceptions on Go-managed
// stacks into panics, so recover() never runs and the whole process dies.
// Across 981 arbitrary code blobs that is the normal case, not an edge case:
// each fault would have to be discovered by crashing, and a crash in the parent
// would end the scan before it reached the descriptor that matters. One child
// per descriptor confines a fault to that child; the parent records NO_OUTPUT
// with the exit status and last trace line and continues.
//
// NO DEADLINE. A timeout does not make a hang impossible, it makes it
// invisible: the driver would print TIMEOUT and move on, and the descriptor
// that actually hangs would be buried in a line that looks like every other
// REJECT. A hanging child hangs the run and says so - its trace is streamed
// into the log as it arrives, so the last line names the phase it never came
// back from. Interrupt the run and read the log.
//
// # EXIT CODES
//
// Nothing here calls os.Exit. Both children return their code: 0 after a
// verdict line, 2 for a bad command line, 4 when the module cannot be loaded,
// 5 on bad input or a recovered panic, 6 when no fault handler could be
// installed.
//
// NOTE: -2's child is selected by the PRKF_PROBE_DESC environment variable;
// -6's and -7's children are selected positionally. The ABI (keyLen, wbArgs,
// newWbArgs, callWarbird, loadWarbird, statusOK) is in warbird.go.
package main

import (
   "bufio"
   "bytes"
   "crypto/ecdh"
   "crypto/rand"
   "encoding/binary"
   "encoding/hex"
   "fmt"
   "math/big"
   "os"
   "os/exec"
   "runtime"
   "strconv"
   "strings"
   "time"
   "unsafe"
)

// childT0 is the one package-level value here, and it cannot be inlined: its
// whole job is to capture the process start once, so that every trace line can
// carry a millisecond offset. Reading time.Now() at the trace site would print
// 0ms for every line.
var childT0 = time.Now()

// ------------------------------------------------------- the -7 trial child

// dpWorker is one trial child. It returns the process exit code: 0 after a
// RESULT line, 4 when the module cannot be loaded, 5 on bad input or a
// recovered panic, 6 when no fault handler could be installed.
//
// The recover is not a substitute for checking errors: it exists because a
// panic here would print nothing the parent can parse, and the parent reads
// "no RESULT line" as NONE. Turning it into the ERR line plus code 5 keeps a
// programming error distinguishable from a fault in native code.
func dpWorker(mode string, desc uint32, obfHex, prep string, variant int) (code int) {
   t := dpTag(mode)
   say := func(f string, a ...any) {
      fmt.Printf("%s "+f+"\n", append([]any{t}, a...)...)
   }
   defer func() {
      if r := recover(); r != nil {
         say("ERR %v", r)
         code = 5
      }
   }()

   in, err := dpLoadInputs()
   if err != nil {
      say("ERR %v", err)
      return 5
   }

   base, err := loadWarbird()
   if err != nil {
      say("ERR %v", err)
      return 4
   }

   patched, skipped := 0, 0
   if prep != "none" {
      for _, s := range in.seg {
         if uint64(s.rva)+uint64(s.size) > uint64(len(in.img)) {
            continue
         }
         c := rawAt(in.fb, in.secs, s.rva, s.size)
         if c == nil || bytes.Equal(in.img[s.rva:s.rva+s.size], c) {
            continue
         }
         runs := []imgRun{{s.rva, s.size}}
         if prep != "full" {
            runs = carveRuns(in.merged, s.rva, s.size)
            if len(runs) == 0 {
               skipped++
            }
         }
         for _, x := range runs {
            if wbPatch(base, x.start, in.img[x.start:x.start+x.length]) {
               patched++
            } else {
               skipped++
            }
         }
      }
   }
   say("PREP %s patched %d skipped %d", prep, patched, skipped)

   if !wbVEH(base, func(s string) { say("%s", s) }) {
      say("ERR AddVectoredExceptionHandler returned NULL - a fault would be invisible")
      return 6
   }

   // op3 is not newWbArgs: it passes a variable args length (the whole point of
   // the variant matrix) and writes a second size dword at +0x2C, which is
   // wbArgs's blank padding and therefore unaddressable from Go.
   op3 := func(descRVA, ln uint32, status, key, out []byte, size2 *uint32) uint32 {
      var a [0x40]byte
      binary.LittleEndian.PutUint64(a[0x00:], 3)
      binary.LittleEndian.PutUint64(a[0x08:], uint64(base)+uint64(descRVA))
      binary.LittleEndian.PutUint64(a[0x10:], uint64(uintptr(unsafe.Pointer(&status[0]))))
      binary.LittleEndian.PutUint64(a[0x18:], uint64(uintptr(unsafe.Pointer(&key[0]))))
      binary.LittleEndian.PutUint32(a[0x20:], 0x20)
      binary.LittleEndian.PutUint64(a[0x24:], uint64(uintptr(unsafe.Pointer(&out[0]))))
      if size2 != nil {
         binary.LittleEndian.PutUint32(a[0x2C:], *size2)
      }
      r, _, _ := wbNtQuery.Call(0xB9, uintptr(unsafe.Pointer(&a[0])), uintptr(ln), 0)
      runtime.KeepAlive(a)
      runtime.KeepAlive(status)
      runtime.KeepAlive(key)
      runtime.KeepAlive(out)
      return uint32(r)
   }

   if mode == "s1" {
      st := make([]byte, 0x40)
      kb := make([]byte, 0x40)
      ob := make([]byte, 0x40)
      copy(kb, in.prv[:0x20])

      rc := op3(desc, 0x2C, st, kb, ob, nil)
      sd := st[:4]
      var zero [0x20]byte
      if rc != 0 || !statusOK(sd) || bytes.Equal(ob[:0x20], zero[:]) {
         say("REJECT rc=0x%08x st=%s out=%s",
            rc, hex.EncodeToString(sd), hex.EncodeToString(ob[:0x20]))
      } else {
         say("OK %s", hex.EncodeToString(ob[:0x20]))
      }
      return 0
   }

   obf, err := hex.DecodeString(obfHex)
   if err != nil {
      say("ERR %v", err)
      return 5
   }

   var in1, in2 []byte
   switch variant {
   case 2:
      in1, in2 = make([]byte, 0x20), make([]byte, 0x20)
   case 1:
      in1, in2 = obf, make([]byte, 0x20)
   default:
      in1, in2 = obf, in.prv[0x20:0x40]
   }

   ln := uint32(0x30)
   if variant == 3 {
      ln = 0x2C
   }

   st2 := make([]byte, 0x40)
   ib := make([]byte, 0x40)
   ob2 := make([]byte, 0x40)
   copy(ib, in1)
   copy(ob2, in2)

   var s2 *uint32
   if variant != 3 {
      v := uint32(0x20)
      s2 = &v
   }

   if rc := op3(desc, ln, st2, ib, ob2, s2); rc != 0 || !statusOK(st2) {
      say("REJECT var=%d rc=0x%08x st=%s", variant, rc, hex.EncodeToString(st2[:4]))
      return 0
   }
   mut := ib[:0x20]

   // stage 3: 64 per-nibble subtables, stage 4: 16-entry permutation
   nibs := func(x []byte) []byte {
      ns := make([]byte, 64)
      for i := range ns {
         sh := uint(0)
         if i%2 == 0 {
            sh = 4
         }
         ns[i] = x[i>>1] >> sh & 0xF
      }
      return ns
   }
   pack := func(ns []byte) []byte {
      out := make([]byte, 32)
      for i := 0; i < 64; i += 2 {
         out[i/2] = ns[i]<<4 | ns[i+1]
      }
      return out
   }

   nm := nibs(mut)
   mp := make([]byte, 64)
   for i := range mp {
      mp[i] = in.img[int(in.cluster)+i*16+int(nm[i])]
   }
   mapped := pack(mp)

   nn := nibs(mapped)
   pl := make([]byte, 64)
   for i := range pl {
      v, ok := in.mapt[int(nn[i])]
      if !ok {
         panic(fmt.Sprintf("KeyError: %d", nn[i]))
      }
      pl[i] = byte(v)
   }
   plain := pack(pl)

   d := new(big.Int).SetBytes(plain)
   res := "NOMATCH"
   priv, err := ecdh.P256().NewPrivateKey(d.FillBytes(make([]byte, 32)))
   if err == nil && bytes.Equal(priv.PublicKey().Bytes()[1:], in.pub) {
      res = "MATCH"
   }
   say("%s var=%d mut=%s mapped=%s plain=%s", res, variant,
      hex.EncodeToString(mut),
      hex.EncodeToString(mapped),
      hex.EncodeToString(plain))
   return 0
}

// ------------------------------------------------------------ the -2 probe

// probeTarget reports whether this process was started as a probe child, and
// for which descriptor. Called from main before the FlagSet exists.
//
// The variable is used instead of a flag so the child mode never appears in
// `prkf -h`; it is written by runChild and by nothing else. A malformed value is
// returned rather than exited on: main is the only place in the program that
// terminates, and it already knows the exit code for a bad command line.
func probeTarget() (uint32, bool, error) {
   s := os.Getenv("PRKF_PROBE_DESC")
   if s == "" {
      return 0, false, nil
   }
   v, err := strconv.ParseUint(s, 0, 32)
   if err != nil {
      return 0, true, fmt.Errorf("PRKF_PROBE_DESC=%q: %w", s, err)
   }
   return uint32(v), true, nil
}

// runOne is the probe child's whole body. It returns the process exit code:
// 0 after emit has printed the RESULT line, 2 if the module or a probe could
// not be set up.
func runOne(descVA uint32) int {
   trace("start desc=%#x keyLen=%#x", descVA, keyLen)

   // Two distinct 32-byte inputs: the routine must map them to distinct
   // outputs, which is what distinguishes a transform from a copy.
   inputA := make([]byte, keyLen)
   for i := range inputA {
      inputA[i] = byte(i)
   }
   inputB := make([]byte, keyLen)
   for i := range inputB {
      inputB[i] = byte(keyLen + i)
   }
   trace("inputs built")

   base, err := loadWarbird()
   if err != nil {
      trace("loadWarbird failed: %v", err)
      fmt.Fprintf(os.Stderr, "prkf: %v\n", err)
      return 2
   }
   trace("dll loaded base=%#x", base)

   w := &worker{
      base:   base, // HMODULE == image base for a DLL
      descVA: descVA,
   }

   a, err := w.probe("A", inputA, keyLen)
   if err != nil {
      trace("probe A failed: %v", err)
      fmt.Fprintf(os.Stderr, "prkf: %v\n", err)
      return 2
   }
   b, err := w.probe("B", inputB, keyLen)
   if err != nil {
      trace("probe B failed: %v", err)
      fmt.Fprintf(os.Stderr, "prkf: %v\n", err)
      return 2
   }
   c, err := w.probe("C", inputA, keyLen-1) // one byte short - must be rejected
   if err != nil {
      trace("probe C failed: %v", err)
      fmt.Fprintf(os.Stderr, "prkf: %v\n", err)
      return 2
   }
   trace("all probes done")
   return w.emit(a, b, c, inputA, inputB)
}

// ------------------------------------------------------------ trace + spawn

// trace writes one timestamped line to the child's stderr. Writes to stderr are
// unbuffered syscalls, so the line is out of this process before the next
// statement runs - including when the next statement is the kernel call that
// never returns. The parent streams these lines straight into the log, so the
// last trace line for a descriptor names the phase that stalled.
func trace(format string, a ...any) {
   fmt.Fprintf(os.Stderr, "[pid %d +%dms] %s\n",
      os.Getpid(), time.Since(childT0).Milliseconds(), fmt.Sprintf(format, a...))
}

type childOut struct {
   line    string        // the RESULT line, synthesized if the child died
   elapsed time.Duration // wall clock for the whole child
   exit    string        // "ok" or cmd.Run()'s error
}

// runChild re-executes this binary as the worker for one descriptor.
//
// w receives the child's trace lines as they arrive and writes them to the
// step's log. They are not buffered until the child exits: a child that hangs
// never exits, and the hang is precisely the case where the last line written
// is the only evidence there is.
func runChild(self string, idx int, descVA uint32, w func(string)) childOut {
   cmd := exec.Command(self)
   cmd.Env = append(os.Environ(), "PRKF_PROBE_DESC="+fmt.Sprintf("%#x", descVA))

   var stdout bytes.Buffer
   cmd.Stdout = &stdout

   er, err := cmd.StderrPipe()
   if err != nil {
      return childOut{
         line: fmt.Sprintf("RESULT %#x NO_OUTPUT exit=%v", descVA, err),
         exit: err.Error(),
      }
   }

   t0 := time.Now()
   if err := cmd.Start(); err != nil {
      return childOut{
         line: fmt.Sprintf("RESULT %#x NO_OUTPUT exit=%v", descVA, err),
         exit: err.Error(),
      }
   }

   // Only the last non-empty trace line is ever reported, so it is tracked as
   // the lines arrive rather than by keeping them all.
   var last string
   sc := bufio.NewScanner(er)
   sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
   for sc.Scan() {
      line := sc.Text()
      if s := strings.TrimSpace(line); s != "" {
         last = s
      }
      w(fmt.Sprintf("  trace[%d %#x] %s", idx, descVA, line))
   }
   // sc.Err is the only signal that the trace ended early: a line past the
   // 1 MiB cap, or a read fault on the pipe. Dropped, it would make a
   // truncated trace indistinguishable from a complete one.
   if serr := sc.Err(); serr != nil {
      w(fmt.Sprintf("  trace[%d %#x] TRACE TRUNCATED: %v", idx, descVA, serr))
   }

   // Reading to EOF before Wait is the documented pattern: Wait closes the
   // pipe, so every trace line is in the log before the summary below.
   err = cmd.Wait()
   el := time.Since(t0)

   exit := "ok"
   if err != nil {
      exit = err.Error()
   }

   for _, l := range strings.Split(stdout.String(), "\n") {
      l = strings.TrimRight(l, "\r")
      if strings.HasPrefix(l, "RESULT") {
         return childOut{line: l, elapsed: el, exit: exit}
      }
   }

   // No RESULT line: the child died, or it never got as far as printing one.
   // The last trace line says which phase it was in.
   return childOut{
      line:    fmt.Sprintf("RESULT %#x NO_OUTPUT exit=%s last=%q", descVA, exit, last),
      elapsed: el,
      exit:    exit,
   }
}

type probeResult struct {
   ntstatus uint32
   status   []byte // the 4 status bytes the routine wrote
   out      []byte
   fill     []byte
}

type worker struct {
   base   uintptr
   descVA uint32
}

// emit prints the RESULT line and returns the process exit code, 0.
func (w *worker) emit(a, b, c *probeResult, inputA, inputB []byte) int {
   // sawSuccess is NTSTATUS 0 AND a zero status dword - not NTSTATUS alone.
   okA := a.ntstatus == 0 && statusOK(a.status) &&
      !bytes.Equal(a.out, a.fill) && !bytes.Equal(a.out, inputA)
   okB := b.ntstatus == 0 && statusOK(b.status) &&
      !bytes.Equal(b.out, b.fill) && !bytes.Equal(b.out, inputB)
   okInput := !bytes.Equal(a.out, b.out)
   okReject := !(c.ntstatus == 0 && statusOK(c.status))

   verdict := "REJECT"
   if okA && okB && okInput && okReject {
      verdict = "ACCEPT"
   }
   trace("emit verdict=%s input_dep=%t size_enforced=%t", verdict, okInput, okReject)

   fmt.Printf("RESULT %#x %s "+
      "A(st=%#010x,sv=%s) "+
      "B(st=%#010x,sv=%s) "+
      "C(st=%#010x,sv=%s) "+
      "input_dep=%t size_enforced=%t out=%s\n",
      w.descVA, verdict,
      a.ntstatus, hex.EncodeToString(a.status),
      b.ntstatus, hex.EncodeToString(b.status),
      c.ntstatus, hex.EncodeToString(c.status),
      okInput, okReject,
      hex.EncodeToString(a.out))
   trace("exiting")
   return 0
}

// probe performs one WB heap-exec call. A failure to draw the random fill is
// returned rather than exited on, so the caller decides the exit code.
func (w *worker) probe(tag string, data []byte, size uint32) (*probeResult, error) {
   trace("probe %s begin size=%#x", tag, size)

   fill := make([]byte, keyLen)
   if _, err := rand.Read(fill); err != nil {
      return nil, fmt.Errorf("probe %s: random fill: %w", tag, err)
   }
   keyBuf := make([]byte, keyLen)
   copy(keyBuf, data) // always keyLen bytes; a short data leaves the tail zero
   status := make([]byte, 0x10)
   out := make([]byte, keyLen)
   copy(out, fill)

   args := newWbArgs(uint64(w.base)+uint64(w.descVA), status, keyBuf, out, size)
   trace("probe %s calling kernel op=3 desc=%#x status=%p key=%p out=%p size=%#x",
      tag, w.base+uintptr(w.descVA), &status[0], &keyBuf[0], &out[0], size)

   r1 := callWarbird(args)

   // Reading out here is also what keeps its backing array alive across the
   // call: only its address was handed to the kernel.
   trace("probe %s returned st=%#010x sv=%x out=%x",
      tag, uint32(r1), status[:4], out[:8])

   return &probeResult{
      ntstatus: uint32(r1),
      status:   status[:4], // per-call buffer, never reused, so no copy
      out:      out,
      fill:     fill,
   }, nil
}

// child.go end
