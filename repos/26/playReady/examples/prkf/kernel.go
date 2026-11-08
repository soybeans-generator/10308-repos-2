// kernel.go begin
//go:build windows

// The Warbird kernel interface and the build profile: the one place a Go pointer
// becomes a uintptr, the one fault handler, the op=3 argument block, and the cache
// of everything derived from one DLL build.
//
// # THE CALL
//
// op=1 (segment decrypt) is used by -2 alone and lives in warbird.go. op=3
// (WbHeapExecuteCall) is used by -1, -3 and -6, so its block is wbArgs below.
// Both go through callWarbird or the equivalent, and the pointer conversion is
// confined to one place whose contract is stated.
//
// IMPORTANT: rejection is in the STATUS DWORD, not in NTSTATUS. The routine writes
// 0x80070057 (E_INVALIDARG) to the status pointer and returns normally, so
// NtQuerySystemInformation still returns 0 and a check written as "NTSTATUS != 0"
// never fires. statusOK is the one implementation of it.
//
// # THE FAULT HANDLER
//
// A fault in a descriptor's code is a Windows SEH exception, not a Go panic, so
// recover() never runs. wbVEH installs a first-chance handler that prints a FAULT
// line and exits; without it a fault is a silent process death the parent can only
// record as "no result".
//
// # THE BUILD PROFILE
//
// The cache of everything this program derives from one DLL build, keyed by its
// SHA-256, and the seam between the two halves of the pipeline:
//
//   DLL phase   -1, -2, -3   fill it in; run once per build
//   BLA phase   -4, -5, -6   read it;    run once per sample
//
// THE KEY IS THE DLL'S SHA-256, NEVER THE IMAGE'S. Every LoadLibraryW bakes the
// process load base into IAT slots and relocated fields, so two decrypted images
// of the same DLL do not hash alike. A per-image key would invalidate the cache on
// every run.
//
// Map and Stages are keyed by routine family ("0", "1", "2"): key[0x40] % 3
// selects one of three chains, and each has its own table AND its own stage
// routines. vkey is the only function that builds those keys.
//
// THE CENSUS IS WHY THE PROFILE EXISTS AT ALL. scanDescs hashes several gigabytes,
// and every trial child needs the spans and heap blocks it produces. Caching them
// turns a child from a five-second process into a half-second one, and a fault
// costs a child.
package main

import (
   "crypto/sha256"
   "encoding/binary"
   "encoding/hex"
   "encoding/json"
   "fmt"
   "os"
   "strconv"
   "strings"
   "syscall"
   "unsafe"
)

// keyLen is the only kernel-ABI constant kept at package scope, because every step
// names it: 32 bytes is the P-256 private scalar length, the size -5's routine
// accepts, and the size it tests for itself with `cmp dword ptr [rcx+10h], 20h`.
const keyLen = 0x20

// ----------------------------------------------------------- the build profile

const profileVersion = 5

// wbKernel32 is one LazyDLL for every kernel32 entry point below.
//
// wbVirtualProtect and wbNtQuery are resolved names because both are called from
// hot paths, so a LazyProc built at the call site would be re-resolved by Find on
// every call.
//
// wbMappedName is K32GetMappedFileNameW, not GetMappedFileNameW: the unprefixed
// name lives in psapi.dll, and a LazyProc built for it on kernel32 panics on first
// Call - which here is inside the VEH callback, turning a reported fault into a
// silent process death.
var (
   wbKernel32 = syscall.NewLazyDLL("kernel32.dll")

   wbVirtualProtect = wbKernel32.NewProc("VirtualProtect")
   wbMappedName     = wbKernel32.NewProc("K32GetMappedFileNameW")
   wbAddVEH         = wbKernel32.NewProc("AddVectoredExceptionHandler")
   wbNtQuery        = syscall.NewLazyDLL("ntdll.dll").NewProc("NtQuerySystemInformation")
)

// callWarbird makes one op=3 call and is the only place a Go pointer becomes a
// uintptr for the kernel.
//
// The conversion is unavoidable: Call takes ...uintptr. It needs no
// runtime.KeepAlive because syscall.(*LazyProc).Call is declared
// //go:uintptrescapes, so the compiler treats the converted pointer as escaping
// for the duration of the call.
//
// What that directive does NOT cover is Out: its address is stored as a uintptr
// inside the struct, so the GC cannot follow it, and the caller must keep the
// output buffer live until it has read the result.
func callWarbird(a *wbArgs) uintptr {
   // SystemExtendedProcessInformation (0xB9) is the Warbird call gate.
   r1, _, _ := wbNtQuery.Call(0xB9, uintptr(unsafe.Pointer(a)), 0x34, 0)
   return r1
}

// loadWarbird maps the PlayReady module into this process and resolves the Warbird
// call gate, returning the image base.
//
// The module must be mapped before any call: the descriptor address is relative to
// that image base in this process, not a file offset. The handle is not retained
// or released - the module has to stay mapped for the life of the process.
func loadWarbird() (base uintptr, err error) {
   base, err = wbLoad(dllPath)
   if err != nil {
      return 0, fmt.Errorf("loading %s: %w", dllPath, err)
   }
   // Resolve now, not on first Call: a Find failure inside mustFind panics, and a
   // panic at the call site would look like a fault in the descriptor's code.
   if err := wbNtQuery.Find(); err != nil {
      return 0, fmt.Errorf("NtQuerySystemInformation: %w", err)
   }
   return base, nil
}

// pfDLL reads the module and returns its bytes and hex digest. Every step that
// touches the profile starts here, so the bytes hashed and the image loaded are the
// same read.
func pfDLL() ([]byte, string, error) {
   fb, err := os.ReadFile(dllPath)
   if err != nil {
      return nil, "", err
   }
   sum := sha256.Sum256(fb)
   return fb, hex.EncodeToString(sum[:]), nil
}

// pfSave writes the profile, indented so it can be read by a human: it is small,
// and "which build is cached, and how far did it get" is a question worth being
// able to answer without running anything.
func pfSave(p *dllProfile) error {
   blob, err := json.MarshalIndent(p, "", "  ")
   if err != nil {
      return err
   }
   return os.WriteFile(profilePath, append(blob, '\n'), 0o644)
}

// statusOK reports whether the routine's status dword - the four bytes it writes at
// its own +0x00 - is zero. See the note at the top of the file for why this and not
// NTSTATUS is the rejection signal.
func statusOK(b []byte) bool {
   return len(b) >= 4 && b[0]|b[1]|b[2]|b[3] == 0
}

// vkey is the profile's key for one routine family. JSON object keys must be
// strings, and every writer and reader goes through this one function.
func vkey(v int) string { return strconv.Itoa(v) }

// wbFree releases one reference taken by wbLoad. The error is returned rather than
// swallowed: -2 reloads the module once per heap block, so a leak here is a leak of
// hundreds of mappings.
func wbFree(h uintptr) error { return syscall.FreeLibrary(syscall.Handle(h)) }

// wbLoad maps a module into this process and returns its base address.
//
// LoadLibrary rather than LoadDLL: the *DLL wrapper only exists so a caller can
// resolve exports by name, and nothing here does. An unretained *DLL would let the
// wrapper be collected while the module stays mapped.
func wbLoad(path string) (uintptr, error) {
   h, err := syscall.LoadLibrary(path)
   if err != nil {
      return 0, err
   }
   return uintptr(h), nil
}

// wbMemAt reinterprets an address the OS handed us as an integer.
//
// The direct form unsafe.Pointer(u) is rejected by vet's unsafeptr check, which
// cannot see that these integers are mapped addresses. unsafe.Add is the identity
// on the address and vet accepts it. The pointer never escapes: every caller copies
// immediately.
func wbMemAt(u uintptr) unsafe.Pointer { return unsafe.Add(unsafe.Pointer(nil), u) }

// wbPatch copies buf to base+rva, flipping the containing pages to RWX for the copy
// and restoring the previous protection afterwards.
//
// The restore is part of the operation, not cleanup: a page left writable is a page
// the kernel refuses to take a descriptor from (0xc000000d), so a failed restore is
// reported as a failed patch rather than left for the next call to blame on the
// routine it was about to invoke.
func wbPatch(base uintptr, rva uint32, buf []byte) bool {
   if len(buf) == 0 {
      return true
   }
   const rwx = 0x40 // PAGE_EXECUTE_READWRITE

   p := base + uintptr(rva)
   n := (uintptr(len(buf)) + 0xFFF) &^ 0xFFF

   var old, dummy uint32
   if r, _, _ := wbVirtualProtect.Call(p, n, rwx, uintptr(unsafe.Pointer(&old))); r == 0 {
      return false
   }
   copy(unsafe.Slice((*byte)(wbMemAt(p)), len(buf)), buf)
   r, _, _ := wbVirtualProtect.Call(p, n, uintptr(old), uintptr(unsafe.Pointer(&dummy)))
   return r != 0
}

// wbVEH installs a first-chance handler that reports the fault and exits.
//
// A false return means no handler was installed, and the caller must treat that as
// fatal: with no handler every fault is a plain process death with no output at
// all, which the parent can only record as "no result".
//
// THE os.Exit BELOW IS DELIBERATE AND IS THE PROGRAM'S ONLY ONE OUTSIDE main. The
// callback is invoked by Windows' exception dispatcher, not by Go code, so there is
// no caller to return a code to and no stack of ours to unwind:
//
//   - it cannot return an error - the signature belongs to the OS;
//   - it cannot panic - a panic in a syscall.NewCallback trampoline is a fatal
//     runtime abort, which would replace the FAULT line (the one diagnostic -3 and
//     -6 parse) with a generic crash dump;
//   - it cannot return EXCEPTION_CONTINUE_SEARCH (0) - the fault would fall through
//     to the default handler and kill the process anyway;
//   - it cannot return EXCEPTION_CONTINUE_EXECUTION (-1) - the faulting instruction
//     would be retried forever.
//
// Exiting here is also safe: ExitProcess is legal from a callback thread, and the
// FAULT line is already out because stdout is unbuffered.
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

type dllProfile struct {
   Version     int                       `json:"version"`
   DLLSHA256   string                    `json:"dll_sha256"`
   SizeOfImage uint32                    `json:"size_of_image"`
   Census      *profileCensus            `json:"census,omitempty"`
   Map         map[string]*profileMap    `json:"map,omitempty"`
   Stages      map[string]*profileStages `json:"stages,omitempty"`
}

// pfLoad returns the profile for sha, or an empty one when the file is missing,
// unreadable, or written for a different build.
//
// Only the DLL-phase steps call this. They are about to fill in a section, and
// discarding a stale file costs nothing but the work they were going to redo
// anyway.
func pfLoad(sha string) *dllProfile {
   raw, err := os.ReadFile(profilePath)
   if err != nil {
      return pfNew(sha)
   }
   var p dllProfile
   if err := json.Unmarshal(raw, &p); err != nil {
      return pfNew(sha)
   }
   if p.Version != profileVersion || p.DLLSHA256 != sha {
      return pfNew(sha)
   }
   return &p
}

// pfNew is an empty profile for this build.
func pfNew(sha string) *dllProfile {
   return &dllProfile{Version: profileVersion, DLLSHA256: sha}
}

// pfRequire is pfLoad for the steps that cannot start over: they need the map
// another step filled in. The error names the command that fixes it rather than the
// missing field, because the fix is the same for all of them.
//
// Every family present is validated here rather than in each caller: 16 keys in
// 0..15 mapping to 16 distinct values is a bijection, and stage 4 indexes a table
// with it, so a repeated value would panic inside a child instead of failing here.
func pfRequire(sha string) (*dllProfile, error) {
   raw, err := os.ReadFile(profilePath)
   if err != nil {
      return nil, fmt.Errorf("no %s - run prkf -1, -2 and -3 once for this DLL", profilePath)
   }
   var p dllProfile
   if err := json.Unmarshal(raw, &p); err != nil {
      return nil, fmt.Errorf("%s: %v", profilePath, err)
   }
   if p.DLLSHA256 != sha {
      return nil, fmt.Errorf("%s was built for a different DLL\n"+
         "  profile: %s\n  actual : %s\n"+
         "  the DLL changed, so every cached result is void: re-run -1 through -3",
         profilePath, p.DLLSHA256, sha)
   }
   if len(p.Map) == 0 {
      return nil, fmt.Errorf("%s has no map section - run prkf -3", profilePath)
   }
   for k, pm := range p.Map {
      v, err := strconv.Atoi(k)
      if err != nil || v < 0 || v > 2 {
         return nil, fmt.Errorf("%s: map key %q is not a family index", profilePath, k)
      }
      if pm == nil || len(pm.Map) != 16 {
         return nil, fmt.Errorf("%s: family %d has no usable permutation - run prkf -3", profilePath, v)
      }
      if pm.Consumer == 0 || pm.Cluster < 0x1000 {
         return nil, fmt.Errorf("%s: family %d has no usable map - run prkf -3", profilePath, v)
      }
      var seen uint32
      for mk, mv := range pm.Map {
         mi, err := strconv.Atoi(mk)
         if err != nil || mi < 0 || mi > 15 || mv < 0 || mv > 15 {
            return nil, fmt.Errorf("%s: family %d: bad entry %q -> %d", profilePath, v, mk, mv)
         }
         if seen&(1<<uint(mv)) != 0 {
            return nil, fmt.Errorf("%s: family %d is not a permutation: 0x%x twice", profilePath, v, mv)
         }
         seen |= 1 << uint(mv)
      }
   }
   return &p, nil
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

// profileCensus is the descriptor census, flattened. Spans are the segment ranges
// to patch; Heaps are {va, descVA, codeRVA, codeLen}.
//
// ALL FOUR heap fields are needed. va is the descriptor's own address and
// identifies a candidate; descVA is +0x28 and is what a call inside the image
// targets; the last two locate the code. Storing only the last three left every
// descriptor with va == 0, collapsed the census onto one map key, and made -6
// report "1 heap-exec descriptor".
type profileCensus struct {
   Spans [][2]uint32 `json:"spans"`
   Heaps [][4]uint32 `json:"heaps"`
}

// profileMap is -3's result for one family: the live bijection set, the magic
// sequence recovered from it, and the nibble permutation.
type profileMap struct {
   Cluster  uint32         `json:"cluster"`
   Magic    string         `json:"magic"`
   Map      map[string]int `json:"map"`
   Consumer uint32         `json:"consumer_desc_va"`
}

// profileStages is -6's result for one family, and it records the WHOLE chain
// rather than just the two descriptors.
//
// S1 and S2 are descriptor addresses - what op=3 is handed. K1 and K2 are which
// 0x20-byte half of the sample's key component each stage receives; O1 and O2 are
// which of the two 0x20-byte buffers holds that stage's output. The layout is not
// self-evident from the code - op=3 is handed a key pointer and an output pointer,
// and a routine may write to either or both - so the search tries every
// combination and this is what it records.
type profileStages struct {
   S1 uint32 `json:"s1_desc_va"`
   S2 uint32 `json:"s2_desc_va"`
   K1 int    `json:"s1_key_half"`
   O1 int    `json:"s1_out_buf"`
   K2 int    `json:"s2_key_half"`
   O2 int    `json:"s2_out_buf"`
}

// wbArgs is the kernel WarbirdCallArgs block for op=3. The arguments the routine
// itself sees begin at +0x10, which is why its documented +0x14 output field lands
// at +0x24 here:
//
//   +0x00  op = 3
//   +0x08  descriptor address
//   +0x10  -> status dword   (routine's +0x00)
//   +0x18  -> 32-byte key    (routine's +0x08)
//   +0x20  u32 key size      (routine's +0x10)
//   +0x24  -> output buffer  (routine's +0x14)
//
// Out is a byte array and not a *byte field because +0x24 is not 8-byte aligned:
// Go would insert four bytes of padding before a pointer field and move the output
// pointer to +0x28, where the routine never looks. The struct ends at +0x34; Go
// rounds its size up to 0x38, but the tail is never written and never read,
// because the call is told 0x34.
//
// Status and Key are real *byte fields, so the GC can follow them. Out cannot be,
// which is why the output buffer has a separate lifetime rule; see newWbArgs.
type wbArgs struct {
   Op      uint64  // +0x00
   Desc    uint64  // +0x08
   Status  *byte   // +0x10
   Key     *byte   // +0x18
   KeySize uint32  // +0x20
   Out     [8]byte // +0x24, unaligned: a uintptr to the output buffer
   _       [8]byte // +0x2c, padding
}

// newWbArgs builds the block for one call. All three slices must be non-empty; an
// empty slice panics here, at construction, rather than passing a null pointer to
// the kernel.
//
// Lifetime: status and key are reachable through the struct's pointer fields, so
// keeping the struct alive keeps both buffers alive. out is not - only its address
// is stored, as a uintptr the GC cannot follow - so the caller must keep it live
// until it has read the result.
func newWbArgs(descAddr uint64, status, key, out []byte, size uint32) *wbArgs {
   a := &wbArgs{
      Op:      3,
      Desc:    descAddr,
      Status:  &status[0],
      Key:     &key[0],
      KeySize: size,
   }
   // The only unaligned pointer in the program. The field is a byte array by ABI,
   // so the address has to be written as a uintptr.
   binary.LittleEndian.PutUint64(a.Out[:], uint64(uintptr(unsafe.Pointer(&out[0]))))
   return a
}

// kernel.go end
