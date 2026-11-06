// 3-find-sub.go begin
//go:build windows

// cmdFindSub implements prkf -3.
//
// Locates the signing-key routine's descriptor for this DLL build.
//
// Takes no arguments. It spawns `prkf -one <descVA>` once per candidate
// descriptor, scanWorkers at a time, and reads the RESULT line each child
// prints. The child mode is internal and hidden from `prkf -h`.
//
// The child process is not optional. Two failures it isolates are
// unrecoverable in-process:
//
//   - A fault in the descriptor's code is a Windows SEH exception inside
//     native code, not a Go panic. recover() cannot catch it, and the process
//     would die mid-scan, losing every result so far.
//   - A hung descriptor call cannot be timed out. A goroutine blocked inside
//     NtQuerySystemInformation cannot be cancelled or killed, so probeTimeout
//     is only enforceable by killing a process.
//
// This program does NOT use sample key files. Discovery rests entirely on
// properties of the routine itself, read from its disassembly:
//
//  1. accepts exactly 0x20 bytes and succeeds
//     (the routine begins: cmp dword ptr [rcx+10h], 20h)
//  2. writes its output buffer
//     (it copies the input there, then transforms in place)
//  3. different input -> different output
//     (a key transform cannot ignore its input)
//  4. REJECTS a size other than 0x20
//     (property 1's converse; no generic routine enforces this)
//
// IMPORTANT: rejection is reported in the STATUS DWORD, not in NTSTATUS.
// The routine writes 0x80070057 (E_INVALIDARG) to the status pointer and
// returns normally, so NtQuerySystemInformation still returns 0. A check
// written as "NTSTATUS != 0" will never fire.
//
// Property 4 is the discriminating one - it collapses the large set of
// descriptors that merely return success. Verification against a real key is
// prkf -4's job, not this program's.
//
// The ONLY value that differs between DLL builds is the RVA of the heap
// descriptor holding the routine.
//
// A result of ZERO accepted descriptors, or more than one, is an error to
// investigate - there is no fallback path.
//
// Outputs, both in testdata/:
//
//   prsubs.json     build-specific values, keyed by the DLL sha256
//   findprsub.txt   per-descriptor probe results, for diagnosing a failure
//
// NOTE: this file owns the package-wide dllPath, keyLen and outOff constants;
// prkf -4 uses the same ones rather than redeclaring them.
package main

import (
   "bytes"
   "context"
   "crypto/rand"
   "crypto/sha256"
   "debug/pe"
   "encoding/binary"
   "encoding/hex"
   "encoding/json"
   "errors"
   "fmt"
   "os"
   "os/exec"
   "runtime"
   "sort"
   "strconv"
   "strings"
   "sync"
   "syscall"
   "time"
   "unsafe"
)

const (
   dllPath = `C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll`

   // 32 bytes: the P-256 private scalar length, the size this routine accepts,
   // and the size it tests for itself with `cmp dword ptr [rcx+10h], 20h`.
   keyLen = 0x20

   // The routine reads its output pointer from args+0x14 - i.e. struct+0x24,
   // because the args it sees begin 0x10 into the kernel's WarbirdCallArgs.
   // The read is unaligned, so this value cannot be inferred from alignment.
   outOff = 0x24

   // Size of one Warbird heap-exec descriptor, including its 32-byte digest.
   // The descriptor's own size field holds this same value, which is what
   // makes it usable as a signature.
   descTotal = 0xF0

   // Per-descriptor wall-clock budget for the worker subprocess.
   probeTimeout = 40 * time.Second

   // How many probe subprocesses run at once. Each child loads the DLL and
   // makes three calls, so this trades process-table pressure for wall clock;
   // 8 keeps a typical machine busy without starving it.
   scanWorkers = 8
)

// cmdFindSub is the entry point for prkf -3.
func cmdFindSub(args []string) error {
   if len(args) != 0 {
      return fmt.Errorf("prkf -3 takes no arguments, got %q", args[0])
   }
   return driver()
}

// comma renders n with thousands separators: 10348448 -> 10,348,448.
func comma(n int) string {
   s := strconv.Itoa(n)
   var b strings.Builder
   for i := 0; i < len(s); i++ {
      if i > 0 && (len(s)-i)%3 == 0 && s[i-1] != '-' {
         b.WriteByte(',')
      }
      b.WriteByte(s[i])
   }
   return b.String()
}

func driver() error {
   data, err := os.ReadFile(dllPath)
   if err != nil {
      return err
   }
   sum := sha256.Sum256(data)
   shaHex := hex.EncodeToString(sum[:])

   f, err := pe.NewFile(bytes.NewReader(data))
   if err != nil {
      return fmt.Errorf("parse PE: %w", err)
   }
   defer f.Close()

   secs := peSections(f)
   ranges := sectionRanges(secs)

   logPath := outFile("findprsub.txt")
   logf, err := os.Create(logPath)
   if err != nil {
      return err
   }
   defer logf.Close()
   // *os.File writes are unbuffered, so each line reaches the log as soon as
   // it is written - useful when the scan dies partway through.
   w := func(s string) { fmt.Fprintln(logf, s) }

   w("dll    " + dllPath)
   w("sha256 " + shaHex)
   w("size   " + comma(len(data)))
   w("")

   descs := heapDescs(data, secs, ranges)
   w(fmt.Sprintf("heap descriptors: %d", len(descs)))
   fmt.Printf("heap descriptors: %d\n", len(descs))

   self, err := os.Executable()
   if err != nil {
      return err
   }

   // Probe every descriptor, scanWorkers at a time. Each probe is its own
   // process (see the file comment), so the children share nothing and the
   // parent only collects stdout. Results are stored by descriptor index, so
   // the log and the ACCEPT lines below stay in descriptor order no matter
   // which child finishes first.
   results := make([]childOut, len(descs))

   var (
      mu       sync.Mutex
      done     int
      accepted int
   )

   nw := scanWorkers
   if nw > len(descs) {
      nw = len(descs)
   }
   if nw < 1 {
      nw = 1
   }

   jobs := make(chan int)
   var wg sync.WaitGroup
   wg.Add(nw)
   for i := 0; i < nw; i++ {
      go func() {
         defer wg.Done()
         for i := range jobs {
            res := runChild(self, descs[i].descVA)
            results[i] = res // distinct index per job: no shared write

            mu.Lock()
            done++
            if strings.Contains(res.line, " ACCEPT ") {
               accepted++
            }
            if done%100 == 0 || done == len(descs) {
               fmt.Printf("  %d/%d  accepted=%d\n", done, len(descs), accepted)
            }
            mu.Unlock()
         }
      }()
   }
   for i := range descs {
      jobs <- i
   }
   close(jobs)
   wg.Wait()

   var acc []descriptor
   for i, res := range results {
      w(res.line)
      if res.stderr != "" {
         w("  stderr: " + res.stderr)
      }
      if strings.Contains(res.line, " ACCEPT ") {
         acc = append(acc, descs[i])
         fmt.Println("ACCEPT " + res.line)
      }
   }

   w("")
   w(fmt.Sprintf("accepted: %d", len(acc)))
   for _, d := range acc {
      w(fmt.Sprintf("  desc %#09x code %#09x+%#07x", d.descVA, d.codeRVA, d.codeLen))
   }

   if len(acc) == 0 {
      return errors.New("no descriptor satisfied the signing-key routine's properties\n" +
         "  See the per-descriptor probe results in " + logPath + "\n" +
         "  Either the hardcoded argument layout no longer matches this build,\n" +
         "  or this library does not contain the routine")
   }
   if len(acc) > 1 {
      return fmt.Errorf("%d descriptors satisfied every property - genuinely "+
         "ambiguous; investigate before trusting either", len(acc))
   }

   d := acc[0]
   rec := subRecord{
      SHA256:  shaHex,
      DLLSize: len(data),
      DescVA:  d.descVA,
      CodeRVA: d.codeRVA,
      SegLen:  d.codeLen,
   }

   pretty, err := json.MarshalIndent(rec, "", "  ")
   if err != nil {
      return err
   }
   cachePath := outFile("prsubs.json")
   if err := os.WriteFile(cachePath, pretty, 0o644); err != nil {
      return err
   }
   compact, err := json.Marshal(rec)
   if err != nil {
      return err
   }

   w("")
   w("cache: " + string(compact))
   fmt.Println("written " + logPath)
   fmt.Println("written " + cachePath)
   fmt.Printf("cache: %s\n", compact)
   return nil
}

func firstLine(s string) string {
   for _, l := range strings.Split(s, "\n") {
      l = strings.TrimSpace(l)
      if l == "" {
         continue
      }
      if len(l) > 200 {
         l = l[:200] + "..."
      }
      return l
   }
   return ""
}

func inside(rva, length uint32, ranges []rng) bool {
   lo := uint64(rva)
   hi := lo + uint64(length)
   for _, r := range ranges {
      if r.lo <= lo && hi <= r.hi {
         return true
      }
   }
   return false
}

func runOne(descVA uint32) {
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

   dll, err := syscall.LoadDLL(dllPath)
   if err != nil {
      fmt.Fprintf(os.Stderr, "LoadLibrary %s: %v\n", dllPath, err)
      os.Exit(2)
   }

   w := &worker{
      ntq:    syscall.NewLazyDLL("ntdll.dll").NewProc("NtQuerySystemInformation"),
      base:   uintptr(dll.Handle), // HMODULE == image base for a DLL
      descVA: descVA,
      got:    make(map[string]*probeResult, 3),
   }

   w.probe("A", inputA, keyLen)
   w.probe("B", inputB, keyLen)
   w.probe("C", inputA, keyLen-1) // one byte short - must be rejected
   w.emit(inputA, inputB)
}

func sawSuccess(r *probeResult) bool {
   // Success is NTSTATUS 0 AND a zero status dword - not NTSTATUS alone.
   return r != nil && r.ntstatus == 0 && bytes.Equal(r.status, []byte{0, 0, 0, 0})
}

type childOut struct {
   line   string // the RESULT line, synthesized if the child died
   stderr string // first non-empty stderr line, for the log
}

// runChild re-executes this binary as the worker for one descriptor.
func runChild(self string, descVA uint32) childOut {
   ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
   defer cancel()

   // Hidden worker mode, see isWorkerInvocation in 1-extract-cert.go.
   cmd := exec.CommandContext(ctx, self, "-one", fmt.Sprintf("%#x", descVA))
   var stdout, stderr bytes.Buffer
   cmd.Stdout = &stdout
   cmd.Stderr = &stderr

   // A crash or a timeout is a legitimate REJECT, not a driver error.
   _ = cmd.Run()

   last := ""
   for _, l := range strings.Split(stdout.String(), "\n") {
      l = strings.TrimRight(l, "\r")
      if strings.HasPrefix(l, "RESULT") {
         return childOut{line: l}
      }
      if strings.HasPrefix(l, "PROBE ") {
         last = strings.TrimSpace(strings.TrimPrefix(l, "PROBE "))
      }
   }

   note := firstLine(stderr.String())
   switch {
   case ctx.Err() == context.DeadlineExceeded:
      return childOut{line: fmt.Sprintf("RESULT %#x TIMEOUT (probe %s)", descVA, last), stderr: note}
   case last != "":
      return childOut{line: fmt.Sprintf("RESULT %#x REJECT FAULT (probe %s)", descVA, last), stderr: note}
   default:
      return childOut{line: fmt.Sprintf("RESULT %#x NO_OUTPUT", descVA), stderr: note}
   }
}

// ------------------------------------------------------------- descriptors

type descriptor struct {
   descVA  uint32 // masked with 0x0FFFFFFF (top nibble is a flag)
   codeRVA uint32
   codeLen uint32
}

// heapDescs collects digest-validated Warbird heap-exec descriptors.
//
// Descriptor layout, relative to its base:
//
//   +0x00  32-byte SHA-256 over [0x20, 0xF0)
//   +0x20  u32 total size (0xF0)
//   +0x24  u32 v1 marker (0xFFFFFF00)
//   +0x28  u32 desc_va
//   +0x34  u32 encr_va   (0xF0000000 | code_rva)
//   +0x38  u32 size      (0xF0000000 | code_len)
//
// Only descriptors whose code segment lies entirely inside a mapped section
// are returned, sorted by code RVA.
func heapDescs(data []byte, secs []peSection, ranges []rng) []descriptor {
   type key struct{ va, rva, ln uint32 }
   found := make(map[key]struct{})
   le := binary.LittleEndian

   for _, s := range secs {
      if s.rawSize < descTotal {
         continue
      }
      start := int(s.rawPtr)
      if start >= len(data) {
         continue
      }
      end := start + int(s.rawSize)
      if end > len(data) {
         end = len(data) // clamp to the bytes actually present
      }
      blob := data[start:end]

      for off := 0; off+descTotal <= len(blob); off += 4 {
         if le.Uint32(blob[off+0x20:]) != descTotal {
            continue
         }
         if le.Uint32(blob[off+0x24:]) != 0xFFFFFF00 {
            continue
         }
         body := blob[off+0x20 : off+descTotal]
         sum := sha256.Sum256(body)
         if !bytes.Equal(sum[:], blob[off:off+0x20]) {
            continue
         }
         descVA := le.Uint32(blob[off+0x28:])
         encrVA := le.Uint32(blob[off+0x34:])
         codeSz := le.Uint32(blob[off+0x38:])
         // top nibble of both fields is a flag; the rest is an RVA
         codeRVA := encrVA & 0x0FFFFFFF
         codeLen := codeSz & 0x0FFFFFFF
         if codeLen != 0 && inside(codeRVA, codeLen, ranges) {
            found[key{descVA & 0x0FFFFFFF, codeRVA, codeLen}] = struct{}{}
         }
      }
   }

   out := make([]descriptor, 0, len(found))
   for k := range found {
      out = append(out, descriptor{descVA: k.va, codeRVA: k.rva, codeLen: k.ln})
   }
   sort.SliceStable(out, func(i, j int) bool {
      a, b := out[i], out[j]
      if a.codeRVA != b.codeRVA {
         return a.codeRVA < b.codeRVA
      }
      if a.descVA != b.descVA {
         return a.descVA < b.descVA
      }
      return a.codeLen < b.codeLen
   })
   return out
}

// ---------------------------------------------------------------- PE layout

type peSection struct {
   name                          string
   vaddr, vsize, rawPtr, rawSize uint32
}

func peSections(f *pe.File) []peSection {
   out := make([]peSection, 0, len(f.Sections))
   for _, s := range f.Sections {
      out = append(out, peSection{
         name:    s.Name,
         vaddr:   s.VirtualAddress,
         vsize:   s.VirtualSize,
         rawPtr:  s.Offset, // PointerToRawData
         rawSize: s.Size,   // SizeOfRawData
      })
   }
   return out
}

// ------------------------------------------------------- worker: the probes

type probeResult struct {
   ntstatus uint32
   status   []byte // the 4 status bytes the routine wrote
   out      []byte
   fill     []byte
}

type rng struct{ lo, hi uint64 }

func sectionRanges(secs []peSection) []rng {
   out := make([]rng, 0, len(secs))
   for _, s := range secs {
      extent := uint64(s.vsize)
      if uint64(s.rawSize) > extent {
         extent = uint64(s.rawSize)
      }
      out = append(out, rng{uint64(s.vaddr), uint64(s.vaddr) + extent})
   }
   return out
}

// ---------------------------------------------------------------- driver

type subRecord struct {
   SHA256  string `json:"sha256"`
   DLLSize int    `json:"dll_size"`
   DescVA  uint32 `json:"desc_va"`
   CodeRVA uint32 `json:"code_rva"`
   SegLen  uint32 `json:"seg_len"`
}

type worker struct {
   ntq    *syscall.LazyProc
   base   uintptr
   descVA uint32
   got    map[string]*probeResult
   cur    string
}

func (w *worker) emit(inputA, inputB []byte) {
   a, b, c := w.got["A"], w.got["B"], w.got["C"]
   if a == nil || b == nil || c == nil {
      fmt.Printf("RESULT %#x REJECT INCOMPLETE (probe %s)\n", w.descVA, w.cur)
      os.Exit(0)
   }

   okAccept := sawSuccess(a) && !bytes.Equal(a.out, a.fill) && !bytes.Equal(a.out, inputA)
   okAccept2 := sawSuccess(b) && !bytes.Equal(b.out, b.fill) && !bytes.Equal(b.out, inputB)
   okInput := !bytes.Equal(a.out, b.out)
   okReject := !sawSuccess(c)

   verdict := "REJECT"
   if okAccept && okAccept2 && okInput && okReject {
      verdict = "ACCEPT"
   }

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
   os.Exit(0) // skip deferred cleanup: the worker has nothing to flush
}

// probe performs one WB heap-exec call.
//
// Arg block for the kernel's WarbirdCallArgs with op=3. The arguments the
// routine itself sees begin at +0x10, which is why the routine's documented
// +0x14 output field lands at +0x24 here:
//
//   +0x00  op = 3 (WbHeapExecuteCall)
//   +0x08  descriptor address
//   +0x10  -> status dword
//   +0x18  -> 32-byte key
//   +0x20  u32 key size
//   +0x24  -> output buffer
func (w *worker) probe(tag string, data []byte, size uint32) {
   w.cur = tag
   // Announce progress on stdout. If the descriptor's code faults, this
   // process dies before it can report, and the driver attributes the crash
   // to the last tag seen.
   fmt.Printf("PROBE %s\n", tag)

   fill := make([]byte, keyLen)
   if _, err := rand.Read(fill); err != nil {
      fmt.Fprintf(os.Stderr, "rand: %v\n", err)
      os.Exit(2)
   }
   keyBuf := make([]byte, keyLen)
   copy(keyBuf, data) // always keyLen bytes; a short data leaves the tail zero
   status := make([]byte, 0x10)
   out := make([]byte, keyLen)
   copy(out, fill)

   args := make([]byte, 0x34)
   le := binary.LittleEndian
   le.PutUint64(args[0x00:], 3)
   le.PutUint64(args[0x08:], uint64(w.base)+uint64(w.descVA))
   le.PutUint64(args[0x10:], uint64(uintptr(unsafe.Pointer(&status[0]))))
   le.PutUint64(args[0x18:], uint64(uintptr(unsafe.Pointer(&keyBuf[0]))))
   le.PutUint32(args[0x20:], size)
   le.PutUint64(args[outOff:], uint64(uintptr(unsafe.Pointer(&out[0]))))

   r1, _, _ := w.ntq.Call(0xB9, uintptr(unsafe.Pointer(&args[0])), 0x34, 0)

   // The pointers above are hidden from the GC behind uintptr; keep every
   // backing array alive across the call.
   runtime.KeepAlive(args)
   runtime.KeepAlive(keyBuf)
   runtime.KeepAlive(status)
   runtime.KeepAlive(out)

   sv := make([]byte, 4)
   copy(sv, status[:4])
   w.got[tag] = &probeResult{
      ntstatus: uint32(r1),
      status:   sv,
      out:      out,
      fill:     fill,
   }
}

// 3-find-sub.go end
