// warbird.go begin
//go:build windows

// The Warbird call: the kernel's argument block, the routine's status
// convention, the call itself, and the probe child that exercises one
// descriptor.
//
// prkf -2 and -3 both make this call, and both go through callWarbird, so
// there is exactly one place where a Go pointer becomes a uintptr. That is not
// cosmetic: Proc.Call and LazyProc.Call take ...uintptr, so the conversion
// cannot be avoided, but it can be confined to one function whose contract is
// stated and whose lifetime handling is correct.
//
// The load-and-resolve pair is shared for the same reason: both callers need
// the PlayReady module mapped and the call gate resolved, so loadWarbird does
// it once. It runs in whichever process needs it - the probe child for -2, the
// parent for -3 - so this removes a second copy of the code, not a second copy
// of the work.
//
// # WHY THE PROBE IS A SEPARATE PROCESS
//
// A fault in a descriptor's code is a Windows SEH exception raised inside the
// DLL, not a Go panic. The Go runtime only converts exceptions on Go-managed
// stacks into panics, so recover() never runs and the whole process is
// terminated. Across 981 arbitrary code blobs that is the normal case, not an
// edge case, and no skip list can rescue it: each fault would have to be
// discovered by crashing, and a crash in the parent would end the scan before
// it reached the descriptor that matters.
//
// One child per descriptor confines a fault to that child. The parent sees a
// child with no RESULT line, records NO_OUTPUT with the child's exit status
// and its last trace line, and continues with the next descriptor.
//
// # NO DEADLINE
//
// There is deliberately no timeout on a child. A deadline here does not make a
// hang impossible, it makes it invisible: the driver would print TIMEOUT and
// move on, and the descriptor that actually hangs - the thing worth knowing -
// would be buried in a log line that looks like every other REJECT. A child
// that hangs now hangs the run, and says so: its trace is streamed into
// testdata/findprsub.txt as it arrives, so the last line for that descriptor
// names the phase it never came back from. Interrupt the run and read the log.
//
// # IMPORTANT: rejection is in the STATUS DWORD, not in NTSTATUS
//
// The routine writes 0x80070057 (E_INVALIDARG) to the status pointer and
// returns normally, so NtQuerySystemInformation still returns 0. A check
// written as "NTSTATUS != 0" will never fire. statusOK is the one
// implementation of that check.
//
// NOTE: dllPath is declared in signing.go, which owns the DLL the scan reads;
// this file borrows it for the child. Everything else here is ABI or the
// child's own trace.
package main

import (
   "bufio"
   "bytes"
   "crypto/rand"
   "encoding/binary"
   "encoding/hex"
   "fmt"
   "io"
   "os"
   "os/exec"
   "runtime"
   "strconv"
   "strings"
   "sync"
   "syscall"
   "time"
   "unsafe"
)

const (
   // warbirdOp is op=3 (WbHeapExecuteCall); argsLen is the size of the
   // kernel's call-args struct. Both are kernel ABI, not build data: the DLL
   // and the running kernel must agree on them, so neither can change
   // unilaterally.
   warbirdOp = 3
   argsLen   = 0x34

   // 32 bytes: the P-256 private scalar length, the size this routine accepts,
   // and the size it tests for itself with `cmp dword ptr [rcx+10h], 20h`.
   keyLen = 0x20

   // probeEnv carries a descriptor VA into a probe child. runChild sets it on
   // the children it spawns and nothing else does; the environment is used
   // instead of a flag so the child mode never appears in `prkf -h`.
   probeEnv = "PRKF_PROBE_DESC"
)

// ------------------------------------------------------------ the probe child

var childT0 = time.Now()

// callWarbird makes one op=3 call and is the only place a Go pointer becomes a
// uintptr for the kernel.
//
// The conversion is unavoidable: Call takes ...uintptr, and syscall offers no
// pointer-typed variant.
//
// The KeepAlive is not decorative. Through an interface, the callee's
// directive (go:uintptrescapes) is not visible to the compiler - it does not
// know which implementation runs - so the referent of the converted pointer is
// not kept alive on our behalf. Without this call, a is dead after the
// conversion and its struct, and with it the status and key buffers, may be
// collected while the kernel is using them.
func callWarbird(proc caller, a *wbArgs) (uintptr, uintptr, error) {
   // SystemExtendedProcessInformation (0xB9) is the Warbird call gate.
   // NTSTATUS comes back in r1; the upper half of the register is garbage.
   r1, r2, err := proc.Call(0xB9, uintptr(unsafe.Pointer(a)), argsLen, 0)
   runtime.KeepAlive(a)
   return r1, r2, err
}

// --------------------------------------------------------------- the call

// loadWarbird maps the PlayReady module into this process and resolves the
// Warbird call gate, returning the image base and the resolved procedure.
//
// Both callers need exactly this pair, so it is written once. The module must
// be mapped here before any call: the descriptor is a virtual address relative
// to that image base in this process, not a file offset.
//
// The *DLL handle is not retained or released. The module has to stay mapped
// for the life of the process - releasing it would invalidate the base this
// function returns - and both callers are short-lived.
func loadWarbird() (base uintptr, ntq *syscall.LazyProc, err error) {
   dll, err := syscall.LoadDLL(dllPath)
   if err != nil {
      return 0, nil, fmt.Errorf("loading %s: %w", dllPath, err)
   }

   ntq = syscall.NewLazyDLL("ntdll.dll").NewProc("NtQuerySystemInformation")
   // Resolve now, not on first Call: a Find failure inside mustFind panics, and
   // a panic at the call site would look like a fault in the descriptor's code.
   if err := ntq.Find(); err != nil {
      return 0, nil, fmt.Errorf("NtQuerySystemInformation: %w", err)
   }
   return uintptr(dll.Handle), ntq, nil
}

// probeTarget reports whether this process was started as a probe child, and
// for which descriptor. Called from main before the FlagSet exists.
func probeTarget() (uint32, bool) {
   s := os.Getenv(probeEnv)
   if s == "" {
      return 0, false
   }
   v, err := strconv.ParseUint(s, 0, 32)
   if err != nil {
      fmt.Fprintf(os.Stderr, "prkf: %s=%q: %v\n", probeEnv, s, err)
      os.Exit(2)
   }
   return uint32(v), true
}

func runOne(descVA uint32) {
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

   base, ntq, err := loadWarbird()
   if err != nil {
      trace("loadWarbird failed: %v", err)
      fmt.Fprintf(os.Stderr, "prkf: %v\n", err)
      os.Exit(2)
   }
   trace("dll loaded base=%#x ntq=%#x", base, ntq.Addr())

   w := &worker{
      ntq:    ntq,
      base:   base, // HMODULE == image base for a DLL
      descVA: descVA,
   }

   a := w.probe("A", inputA, keyLen)
   b := w.probe("B", inputB, keyLen)
   c := w.probe("C", inputA, keyLen-1) // one byte short - must be rejected
   trace("all probes done")
   w.emit(a, b, c, inputA, inputB)
}

// sawSuccess: NTSTATUS 0 AND a zero status dword - not NTSTATUS alone. The
// pointer is never nil: probe either returns a result or kills the process.
func sawSuccess(r *probeResult) bool {
   return r.ntstatus == 0 && statusOK(r.status)
}

// statusOK reports whether the routine's status dword - the four bytes it
// writes at its own +0x00 - is zero. See the note at the top of the file for
// why this and not NTSTATUS is the rejection signal.
func statusOK(b []byte) bool {
   return len(b) >= 4 && b[0]|b[1]|b[2]|b[3] == 0
}

// trace writes one timestamped line to the child's stderr. Writes to stderr
// are unbuffered syscalls, so the line is out of this process before the next
// statement runs - including when the next statement is the kernel call that
// never returns. The parent streams these lines straight into the log, so the
// last trace line for a descriptor names the phase that stalled.
func trace(format string, a ...any) {
   fmt.Fprintf(os.Stderr, "[pid %d +%dms] %s\n",
      os.Getpid(), time.Since(childT0).Milliseconds(), fmt.Sprintf(format, a...))
}

// caller is the part of *syscall.Proc and *syscall.LazyProc this program uses.
// Both have identical Call signatures, so one call site covers prkf -2's probe
// and prkf -3's decrypt.
type caller interface {
   Call(a ...uintptr) (r1, r2 uintptr, lastErr error)
}

// ------------------------------------------------------ spawning the children

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
   cmd.Env = append(os.Environ(), probeEnv+"="+fmt.Sprintf("%#x", descVA))

   var stdout bytes.Buffer
   cmd.Stdout = &stdout

   er, ew := io.Pipe()
   cmd.Stderr = ew

   var (
      lines []string
      swg   sync.WaitGroup
   )
   swg.Add(1)
   go func() {
      defer swg.Done()
      sc := bufio.NewScanner(er)
      sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
      for sc.Scan() {
         line := sc.Text()
         lines = append(lines, line)
         w(fmt.Sprintf("  trace[%d %#x] %s", idx, descVA, line))
      }
   }()

   t0 := time.Now()
   err := cmd.Run()
   el := time.Since(t0)

   // Run returned, so the child is gone and exec's copy goroutine has
   // finished. Closing the write end is what gives the scanner its EOF; the
   // WaitGroup makes sure every line is in the log before the summary below.
   ew.Close()
   swg.Wait()

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
   last := ""
   for i := len(lines) - 1; i >= 0; i-- {
      if s := strings.TrimSpace(lines[i]); s != "" {
         last = s
         break
      }
   }
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

// ---------------------------------------------------------------- the ABI

// wbArgs is the kernel WarbirdCallArgs block for op=3. The arguments the
// routine itself sees begin at +0x10, which is why its documented +0x14
// output field lands at +0x24 here:
//
//   +0x00  op = 3
//   +0x08  descriptor address
//   +0x10  -> status dword   (routine's +0x00)
//   +0x18  -> 32-byte key    (routine's +0x08)
//   +0x20  u32 key size      (routine's +0x10)
//   +0x24  -> output buffer  (routine's +0x14)
//
// Out is a byte array and not a *byte field because +0x24 is not 8-byte
// aligned: Go would insert four bytes of padding before a pointer field and
// move the output pointer to +0x28, where the routine never looks. The struct
// ends at +0x34; Go rounds its size up to 0x38, but the tail is never written
// and never read, because the call is told argsLen.
//
// Status and Key are real *byte fields, so the GC can follow them: keeping a
// wbArgs alive keeps both buffers alive. Out cannot be followed, which is why
// the output buffer has a separate lifetime rule; see newWbArgs.
//
// NOTHING CHECKS THE +0x24 OFFSET. It falls out of the field order above, and
// inserting, removing or reordering any field before Out moves it. There is no
// field to add: the five fields above consume exactly +0x24 of the 0x34-byte
// block, so the layout is stable in practice - but a change here is silent at
// compile time and shows up as a successful call with an untouched output
// buffer, which is what newWbArgs's callers test for.
type wbArgs struct {
   Op      uint64  // +0x00
   Desc    uint64  // +0x08
   Status  *byte   // +0x10
   Key     *byte   // +0x18
   KeySize uint32  // +0x20
   Out     [8]byte // +0x24, unaligned: a uintptr to the output buffer
   _       [8]byte // +0x2c, padding
}

// newWbArgs builds the block for one call. All three slices must be non-empty;
// an empty slice panics here, at construction, rather than passing a null
// pointer to the kernel.
//
// Lifetime: status and key are reachable through the struct's pointer fields,
// so callWarbird's KeepAlive covers them. out is not - only its address is
// stored, as a uintptr the GC cannot follow - so the caller must keep out live
// until it has read the result. Both call sites do, because reading the output
// is the whole point of the call.
func newWbArgs(descAddr uint64, status, key, out []byte, size uint32) *wbArgs {
   a := &wbArgs{
      Op:      warbirdOp,
      Desc:    descAddr,
      Status:  &status[0],
      Key:     &key[0],
      KeySize: size,
   }
   // The only unaligned pointer in the program. The field is a byte array by
   // ABI, so the address has to be written as a uintptr.
   binary.LittleEndian.PutUint64(a.Out[:], uint64(uintptr(unsafe.Pointer(&out[0]))))
   return a
}

type worker struct {
   ntq    *syscall.LazyProc
   base   uintptr
   descVA uint32
}

func (w *worker) emit(a, b, c *probeResult, inputA, inputB []byte) {
   okAccept := sawSuccess(a) && !bytes.Equal(a.out, a.fill) && !bytes.Equal(a.out, inputA)
   okAccept2 := sawSuccess(b) && !bytes.Equal(b.out, b.fill) && !bytes.Equal(b.out, inputB)
   okInput := !bytes.Equal(a.out, b.out)
   okReject := !sawSuccess(c)

   verdict := "REJECT"
   if okAccept && okAccept2 && okInput && okReject {
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
   os.Exit(0) // skip deferred cleanup: the worker has nothing to flush
}

// probe performs one WB heap-exec call.
func (w *worker) probe(tag string, data []byte, size uint32) *probeResult {
   trace("probe %s begin size=%#x", tag, size)

   fill := make([]byte, keyLen)
   if _, err := rand.Read(fill); err != nil {
      trace("probe %s rand failed: %v", tag, err)
      os.Exit(2)
   }
   keyBuf := make([]byte, keyLen)
   copy(keyBuf, data) // always keyLen bytes; a short data leaves the tail zero
   status := make([]byte, 0x10)
   out := make([]byte, keyLen)
   copy(out, fill)

   args := newWbArgs(uint64(w.base)+uint64(w.descVA), status, keyBuf, out, size)
   trace("probe %s calling kernel op=%d desc=%#x status=%p key=%p out=%p size=%#x",
      tag, warbirdOp, w.base+uintptr(w.descVA), &status[0], &keyBuf[0], &out[0], size)

   r1, _, _ := callWarbird(w.ntq, args)

   // Reading out here is also what keeps its backing array alive across the
   // call: only its address was handed to the kernel.
   trace("probe %s returned st=%#010x sv=%x out=%x",
      tag, uint32(r1), status[:4], out[:8])

   return &probeResult{
      ntstatus: uint32(r1),
      status:   status[:4], // per-call buffer, never reused, so no copy
      out:      out,
      fill:     fill,
   }
}

// warbird.go end
