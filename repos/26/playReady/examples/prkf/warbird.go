// warbird.go begin
//go:build windows

// The Warbird interface: the descriptor format, the PE census that finds
// descriptors in a DLL on disk, the span and block carving, the kernel call ABI
// both branches share, and the one page-patch and one fault handler.
//
// # THE DESCRIPTOR FORMAT
//
// A Warbird descriptor is a 32-byte SHA-256 digest followed by a body, and the
// digest covers [0x20, size) where size is the u32 at +0x20. That makes every
// descriptor self-validating, which is what lets this program enumerate them
// with no external symbol data at all.
//
//   +0x00  32-byte SHA-256 over [0x20, size)
//   +0x20  u32 total size   (0xF0 => heap-exec, anything else => segment)
//   +0x24  u32 v1 marker    (0xFFFFFF00)
//   +0x28  u32 desc_va
//   +0x2C  u32 relocs, +0x30 u32 count   (segment descriptors only)
//   +0x34  u32 encr_va      (0xF0000000 | code_rva; heap-exec only)
//   +0x38  u32 size         (0xF0000000 | code_len; heap-exec only)
//   +0xF0  entries, 0xC each: flags, rva, size   (segment descriptors only)
//
// The top nibble of desc_va, encr_va and an entry's size is a flag; the rest is
// an RVA. scanDescs returns every descriptor whose digest validates, in file
// order; segSpans returns a segment descriptor's entry spans. The v1 marker is
// covered by the digest, so it is documented but not tested: testing it could
// only reject descriptors the kernel accepts.
//
// # THE TWO CALLS
//
// op=1 (segment decrypt) is used by -5 alone, and its block lives in image.go
// because it is the only caller. op=3 (WbHeapExecuteCall) is used by -2's probe
// child and by -3, so its block is wbArgs below. Both go through one function
// that converts a Go pointer to a uintptr: Call takes ...uintptr, so the
// conversion cannot be avoided, but it can be confined to one place whose
// contract is stated and whose lifetime handling is correct.
//
// IMPORTANT: rejection is in the STATUS DWORD, not in NTSTATUS. The routine
// writes 0x80070057 (E_INVALIDARG) to the status pointer and returns normally,
// so NtQuerySystemInformation still returns 0, and a check written as
// "NTSTATUS != 0" will never fire. statusOK is the one implementation of it.
//
// # EXIT CODES
//
// os.Exit appears exactly twice in the program: in main, and in the wbVEH
// callback. Every worker returns an int instead, so the exit code is part of a
// signature rather than a hidden jump. The callback is the one exception and
// cannot be otherwise - see wbVEH.
//
// NOTE: dllPath is declared in main.go's manifest. Everything here is either
// the on-disk descriptor format or kernel ABI.
package main

import (
   "bytes"
   "crypto/sha256"
   "encoding/binary"
   "encoding/hex"
   "fmt"
   "os"
   "runtime"
   "sort"
   "strings"
   "syscall"
   "unsafe"
)

const (
   // descTotal is the total size of a heap-exec descriptor, digest included.
   // The descriptor's own size field holds this same value, which is what makes
   // 0xF0 a signature rather than a guess: every other value belongs to a
   // segment descriptor.
   descTotal = 0xF0

   // warbirdOp is op=3 (WbHeapExecuteCall); argsLen is the size of the kernel's
   // call-args struct. Both are kernel ABI, not build data: the DLL and the
   // running kernel must agree on them, so neither can change unilaterally.
   warbirdOp = 3
   argsLen   = 0x34

   // 32 bytes: the P-256 private scalar length, the size -3's routine accepts,
   // and the size it tests for itself with `cmp dword ptr [rcx+10h], 20h`.
   keyLen = 0x20

   // PAGE_EXECUTE_READWRITE
   wbPAGE_RWX = 0x40
)

// One entry point per native routine the program calls, shared by every step
// that needs it. Declaring them here rather than per file is what lets wbPatch
// and wbVEH exist once: three files patch pages and two install a fault
// handler, and they all have to agree about which kernel32 they are calling.
//
// K32GetMappedFileNameW, not GetMappedFileNameW: the unprefixed name lives in
// psapi.dll, and a LazyProc built for it on kernel32 panics on first Call -
// which here is inside the VEH callback, turning a reported fault into a silent
// process death.
var (
   wbKernel32 = syscall.NewLazyDLL("kernel32.dll")
   wbNtdll    = syscall.NewLazyDLL("ntdll.dll")

   wbVirtualProtect = wbKernel32.NewProc("VirtualProtect")
   wbMappedName     = wbKernel32.NewProc("K32GetMappedFileNameW")
   wbAddVEH         = wbKernel32.NewProc("AddVectoredExceptionHandler")
   wbNtQuery        = wbNtdll.NewProc("NtQuerySystemInformation")
)

// callWarbird makes one op=3 call and is the only place a Go pointer becomes a
// uintptr for the kernel.
//
// The conversion is unavoidable: Call takes ...uintptr, and syscall offers no
// pointer-typed variant.
//
// The KeepAlive is not decorative. Through the wbArgs pointer the callee's
// directive (go:uintptrescapes) is not visible to the compiler, so the referent
// of the converted pointer is not kept alive on our behalf. Without this call,
// a is dead after the conversion and its struct, and with it the status and key
// buffers, may be collected while the kernel is using them.
//
// NTSTATUS comes back in r1; the upper half of the register is garbage. The
// third return of Call is GetLastError, which NtQuerySystemInformation does not
// set, so there is nothing there to check.
func callWarbird(a *wbArgs) uintptr {
   // SystemExtendedProcessInformation (0xB9) is the Warbird call gate.
   r1, _, _ := wbNtQuery.Call(0xB9, uintptr(unsafe.Pointer(a)), argsLen, 0)
   runtime.KeepAlive(a)
   return r1
}

func le16(b []byte, o int) uint16 {
   return binary.LittleEndian.Uint16(b[o:])
}

func le32(b []byte, o int) uint32 {
   return binary.LittleEndian.Uint32(b[o:])
}

// loadWarbird maps the PlayReady module into this process and resolves the
// Warbird call gate, returning the image base.
//
// Both callers need exactly this, so it is written once. The module must be
// mapped here before any call: the descriptor is a virtual address relative to
// that image base in this process, not a file offset.
//
// The *DLL handle is not retained or released. The module has to stay mapped
// for the life of the process - releasing it would invalidate the base this
// function returns - and both callers are short-lived.
func loadWarbird() (base uintptr, err error) {
   dll, err := syscall.LoadDLL(dllPath)
   if err != nil {
      return 0, fmt.Errorf("loading %s: %w", dllPath, err)
   }

   // Resolve now, not on first Call: a Find failure inside mustFind panics, and
   // a panic at the call site would look like a fault in the descriptor's code.
   if err := wbNtQuery.Find(); err != nil {
      return 0, fmt.Errorf("NtQuerySystemInformation: %w", err)
   }
   return uintptr(dll.Handle), nil
}

// rawAt returns the file's own bytes for an RVA, or nil when the RVA is not
// backed by a section's raw data. Callers compare it against the decrypted
// image to decide whether a span needs patching at all.
func rawAt(fb []byte, secs []imgSection, rva, n uint32) []byte {
   for _, s := range secs {
      if s.va <= rva && rva < s.va+s.rs {
         if o := int(s.rp) + int(rva-s.va); o+int(n) <= len(fb) {
            return fb[o : o+int(n)]
         }
      }
   }
   return nil
}

// statusOK reports whether the routine's status dword - the four bytes it
// writes at its own +0x00 - is zero. See the note at the top of the file for
// why this and not NTSTATUS is the rejection signal.
func statusOK(b []byte) bool {
   return len(b) >= 4 && b[0]|b[1]|b[2]|b[3] == 0
}

// ------------------------------------------------------- raw memory + faults

// wbMemAt reinterprets an address the OS handed us as an integer.
//
// The direct form unsafe.Pointer(u) is rejected by vet's unsafeptr check, which
// cannot see that these integers are mapped addresses. unsafe.Add is the
// identity on the address and vet accepts it. The pointer never escapes: every
// caller copies immediately, so the slice header holding the foreign address
// dies on the caller's stack frame.
func wbMemAt(u uintptr) unsafe.Pointer {
   return unsafe.Add(unsafe.Pointer(nil), u)
}

// wbPatch copies buf to base+rva, flipping the containing pages to RWX for the
// copy and restoring the previous protection afterwards.
//
// The restore is part of the operation, not cleanup: a page left writable is a
// page the kernel refuses to take a descriptor from (0xc000000d), so a failed
// restore is reported as a failed patch rather than left for the next call to
// blame on the routine it was about to invoke.
func wbPatch(base uintptr, rva uint32, buf []byte) bool {
   if len(buf) == 0 {
      return true
   }
   p := base + uintptr(rva)
   n := (uintptr(len(buf)) + 0xFFF) &^ 0xFFF

   var old, dummy uint32
   if r, _, _ := wbVirtualProtect.Call(p, n, wbPAGE_RWX, uintptr(unsafe.Pointer(&old))); r == 0 {
      return false
   }
   copy(unsafe.Slice((*byte)(wbMemAt(p)), len(buf)), buf)
   r, _, _ := wbVirtualProtect.Call(p, n, uintptr(old), uintptr(unsafe.Pointer(&dummy)))
   return r != 0
}

// wbVEH installs a first-chance handler that reports the fault and exits.
//
// A false return means no handler was installed, and the caller must treat that
// as fatal: with no handler every fault is a plain process death with no output
// at all, which the parent can only record as "no result" - the exact ambiguity
// the FAULT line exists to remove.
//
// THE os.Exit BELOW IS DELIBERATE AND IS THE PROGRAM'S ONLY ONE OUTSIDE main.
// The callback is invoked by Windows' exception dispatcher, not by Go code, so
// there is no caller to return a code to and no stack of ours to unwind:
//
//   - it cannot return an error - the signature belongs to the OS, and the
//     dispatcher would ignore it;
//   - it cannot panic - a panic in a syscall.NewCallback trampoline is a fatal
//     runtime abort, which would replace the FAULT line (the one diagnostic
//     -6 and -7 parse) with a generic crash dump;
//   - it cannot return EXCEPTION_CONTINUE_SEARCH (0) - the fault would fall
//     through to the default handler and kill the process anyway, possibly
//     behind a Windows Error Reporting dialog that hangs a batch run;
//   - it cannot return EXCEPTION_CONTINUE_EXECUTION (-1) - the faulting
//     instruction would be retried forever.
//
// Exiting here is also safe: ExitProcess is legal from a callback thread, and
// the FAULT line is already out because stdout is unbuffered.
func wbVEH(base uintptr, say func(string)) bool {
   cb := syscall.NewCallback(func(ep *excPointers) uintptr {
      mod := "-"
      var nm [512]uint16
      if r, _, _ := wbMappedName.Call(^uintptr(0), ep.Record.Address,
         uintptr(unsafe.Pointer(&nm[0])), 512); r != 0 {
         if s := syscall.UTF16ToString(nm[:]); s != "" {
            mod = s[strings.LastIndexByte(s, '\\')+1:]
         }
      }

      raw := "-"
      if ep.Record.Address != 0 {
         raw = hex.EncodeToString(unsafe.Slice((*byte)(wbMemAt(ep.Record.Address)), 16))
      }

      say(fmt.Sprintf("FAULT 0x%08x addr=0x%016x off=%+#x module=%s bytes=%s",
         ep.Record.Code, ep.Record.Address,
         int64(ep.Record.Address)-int64(base), mod, raw))
      os.Exit(3)
      return 0
   })
   h, _, _ := wbAddVEH.Call(1, cb)
   return h != 0
}

// excPointers and excRecord are EXCEPTION_POINTERS and the head of
// EXCEPTION_RECORD. Nothing past ExceptionAddress is dereferenced.
type excPointers struct {
   Record  *excRecord
   Context uintptr
}

type excRecord struct {
   Code    uint32
   Flags   uint32
   Prev    uintptr
   Address uintptr
}

// ------------------------------------------------------------- descriptors

// imgDesc is one digest-validated descriptor. rva and ln are meaningful only
// for heap-exec descriptors; off and size are meaningful for both, because the
// segment call reads the descriptor's own relocation fields and -5 rewrites a
// descriptor in place. descVA is the +0x28 field - the address the kernel is
// asked to execute - and is meaningful only for heap-exec descriptors.
type imgDesc struct {
   va     uint32 // descriptor RVA
   off    uint32 // file offset of the descriptor
   size   uint32 // total size, digest included
   descVA uint32 // +0x28, top nibble masked (heap-exec only)
   rva    uint32 // code RVA     (heap-exec only)
   ln     uint32 // code length  (heap-exec only)
}

// scanDescs returns every digest-validated descriptor in the file, in the order
// the sections and their bytes appear.
//
// A candidate is accepted when its size field is plausible and the SHA-256 over
// [0x20, size) matches the digest that precedes it. Nothing else is checked:
// the digest is the signature, so a descriptor that passes is a descriptor the
// kernel will accept, and one that fails is not worth classifying.
//
// The 0x200000 cap is deliberate and must not be lowered. The two largest
// descriptors on the recorded build are 0x829c and 0x3cac bytes; a 0x2000 cap
// silently skips them, which loses the gap blocks 0x334290..0x3370ef and makes
// -7 execute ciphertext.
func scanDescs(fb []byte, secs []imgSection) []imgDesc {
   var out []imgDesc
   for _, s := range secs {
      lo := int(s.rp)
      hi := min(lo+int(s.rs), len(fb))
      if hi <= lo {
         continue
      }
      b := fb[lo:hi]

      for off := 0; off < len(b)-0x40; off += 4 {
         size := le32(b, off+0x20)
         if size < 0x40 || size > 0x200000 || off+int(size) > len(b) {
            continue
         }
         sum := sha256.Sum256(b[off+0x20 : off+int(size)])
         if !bytes.Equal(sum[:], b[off:off+32]) {
            continue
         }

         // top nibble of desc_va and of both heap-exec fields is a flag; the
         // rest is an RVA
         d := imgDesc{
            va:     s.va + uint32(off),
            off:    s.rp + uint32(off),
            size:   size,
            descVA: le32(b, off+0x28) & 0x0FFFFFFF,
         }
         if d.heap() {
            d.rva = le32(b, off+0x34) & 0x0FFFFFFF
            d.ln = le32(b, off+0x38) & 0x0FFFFFFF
         }
         out = append(out, d)
      }
   }
   return out
}

// splitDescs partitions a census into segment and heap-exec descriptors, in file
// order. -2, -5, -6 and -7 all need exactly this split and nothing else, so it
// is written once here rather than four times in the steps.
func splitDescs(fb []byte, secs []imgSection) (segs, heaps []imgDesc) {
   for _, d := range scanDescs(fb, secs) {
      if d.heap() {
         heaps = append(heaps, d)
      } else {
         segs = append(segs, d)
      }
   }
   return segs, heaps
}

// heap reports whether this is a heap-exec descriptor. 0xF0 is the only size
// the kernel treats that way, and the size field is covered by the digest, so
// the test cannot be spoofed by a corrupt byte.
func (d imgDesc) heap() bool {
   return d.size == descTotal
}

// imgInterval is a half-open RVA range: one heap-exec block, or a merged run of
// them.
type imgInterval struct{ lo, hi uint32 }

// heapIntervals turns heap-exec descriptors into the RVA ranges the kernel
// decrypts itself, ready for mergeIntervals. -6 and -7 both patch segment spans
// around exactly these ranges.
func heapIntervals(heaps []imgDesc) []imgInterval {
   var ivs []imgInterval
   for _, h := range heaps {
      if h.ln != 0 {
         ivs = append(ivs, imgInterval{h.rva, h.rva + h.ln})
      }
   }
   return ivs
}

// mergeIntervals sorts and coalesces ranges, so carveRuns can binary-search
// them.
func mergeIntervals(ivs []imgInterval) []imgInterval {
   sort.Slice(ivs, func(i, j int) bool { return ivs[i].lo < ivs[j].lo })

   var out []imgInterval
   for _, p := range ivs {
      if n := len(out); n > 0 && p.lo <= out[n-1].hi {
         out[n-1].hi = max(out[n-1].hi, p.hi)
         continue
      }
      out = append(out, p)
   }
   return out
}

// imgRun is a half-open RVA range that is safe to patch.
type imgRun struct{ start, length uint32 }

// carveRuns returns [r, r+s) minus every interval, as the runs that remain.
//
// Both patching callers need this, and both need it for the same reason: the
// kernel decrypts a heap-exec block itself on op=3, so copying already-decrypted
// bytes over one causes a double decrypt and the routine executes garbage.
func carveRuns(merged []imgInterval, r, s uint32) []imgRun {
   var out []imgRun
   cur, end := r, r+s
   i := max(sort.Search(len(merged), func(i int) bool { return merged[i].lo > r })-1, 0)

   for _, m := range merged[i:] {
      if m.hi <= cur {
         continue
      }
      if m.lo >= end {
         break
      }
      if m.lo > cur {
         out = append(out, imgRun{cur, min(m.lo, end) - cur})
      }
      if cur = max(cur, m.hi); cur >= end {
         break
      }
   }
   if cur < end {
      out = append(out, imgRun{cur, end - cur})
   }
   return out
}

// imgSection is one PE section header as mapped: virtual address, virtual size,
// raw extent and raw file offset.
type imgSection struct {
   va uint32
   vs uint32 // VirtualSize
   rs uint32 // SizeOfRawData
   rp uint32 // PointerToRawData
}

// peSections reads SizeOfImage and the section table out of a PE file.
//
// A short or malformed header returns no sections and a zero SizeOfImage rather
// than panicking: all four callers pass a ReadFile result straight in, and a
// partially read file (still being written, or truncated by a copy) would
// otherwise die with a bare slice-bounds error that names the wrong culprit.
// Every caller already treats an empty section list or a zero SizeOfImage as
// fatal, so nothing downstream needs a new check.
func peSections(fb []byte) (sizeImg uint32, secs []imgSection) {
   if len(fb) < 0x40 {
      return 0, nil
   }
   lf := int(le32(fb, 0x3C)) // e_lfanew
   // One bound covers every header field read below: NumberOfSections at
   // lf+6, SizeOfOptionalHeader at lf+20, and SizeOfImage at lf+24+56.
   if lf < 0 || lf+24+60 > len(fb) {
      return 0, nil
   }
   n := int(le16(fb, lf+6))     // NumberOfSections
   opt := int(le16(fb, lf+20))  // SizeOfOptionalHeader
   sizeImg = le32(fb, lf+24+56) // SizeOfImage

   p := lf + 24 + opt
   if n <= 0 || p+40*n > len(fb) {
      return sizeImg, nil
   }
   secs = make([]imgSection, n)
   for i := range secs {
      secs[i] = imgSection{
         va: le32(fb, p+12),
         vs: le32(fb, p+8),
         rs: le32(fb, p+16),
         rp: le32(fb, p+20),
      }
      p += 40
   }
   return sizeImg, secs
}

// imgSpan is one RVA range listed by a segment descriptor.
type imgSpan struct{ rva, size uint32 }

// segSpans returns the RVA ranges a segment descriptor lists. Each entry is
// 0xC bytes from +0xF4: flags, rva, size. Entries that reach outside the image
// are dropped rather than clamped.
//
// Callers that need one span per RVA must dedupe themselves. -5 must not: its
// descriptors list overlapping spans, and deduping by RVA loses the later,
// larger ones. -7 does, because it patches each range once.
func segSpans(fb []byte, d imgDesc, sizeImg uint32) []imgSpan {
   if int(d.off)+int(d.size) > len(fb) {
      return nil
   }
   b := fb[d.off : d.off+d.size]

   var out []imgSpan
   for o := 0xF4; o+0xC <= len(b); o += 0xC {
      rva, size := le32(b, o+4), le32(b, o+8)
      if rva >= 0x1000 && size >= 8 && uint64(rva)+uint64(size) <= uint64(sizeImg) {
         out = append(out, imgSpan{rva, size})
      }
   }
   return out
}

// ---------------------------------------------------------------- the ABI

// wbArgs is the kernel WarbirdCallArgs block for op=3. The arguments the
// routine itself sees begin at +0x10, which is why its documented +0x14 output
// field lands at +0x24 here:
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

// warbird.go end
