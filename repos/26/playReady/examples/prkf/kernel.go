// kernel.go begin
//go:build windows

// The Warbird kernel interface.
//
// op=1 (segment decrypt) is -2's and lives in warbird.go. op=3 (WbHeapExecuteCall) is op3Call,
// used by -1, -3 and -4.
//
// REJECTION IS IN THE STATUS DWORD, NOT NTSTATUS: the routine writes 0x80070057
// (E_INVALIDARG) to the status pointer and returns normally, so NtQuerySystemInformation still
// returns 0 and a check written as "NTSTATUS != 0" never fires.
//
// A FAULT IN A DESCRIPTOR'S CODE IS A WINDOWS SEH EXCEPTION, not a Go panic: recover() never
// runs. wbVEH turns it into a fault row.
//
// THE TYPES THE FILES ON DISK HAVE - dllProfile, profileCensus, profileMap, profileStages -
// LIVE IN profile.go, because -5..-7 read them on every platform. This file only holds what
// needs Windows.
package main

import (
   "crypto/sha256"
   "encoding/binary"
   "encoding/hex"
   "encoding/json"
   "fmt"
   "os"
   "runtime"
   "strings"
   "syscall"
   "unsafe"
)

// dllPath is the PlayReady module. It stays outside outDir: a descriptor is an RVA into the
// mapped image, so the bytes hashed and the image the Warbird gate executes must be the same
// module.
const dllPath = `C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll`

var (
   wbKernel32 = syscall.NewLazyDLL("kernel32.dll")

   wbVirtualProtect = wbKernel32.NewProc("VirtualProtect")
   // K32GetMappedFileNameW, not GetMappedFileNameW: the unprefixed name lives in psapi.dll,
   // and a LazyProc built for it on kernel32 panics on first Call - which here is inside the
   // VEH callback, turning a reported fault into a silent death.
   wbMappedName   = wbKernel32.NewProc("K32GetMappedFileNameW")
   wbAddVEH       = wbKernel32.NewProc("AddVectoredExceptionHandler")
   wbVirtualQuery = wbKernel32.NewProc("VirtualQuery")
   wbReadProc     = wbKernel32.NewProc("ReadProcessMemory")
   wbNtQuery      = syscall.NewLazyDLL("ntdll.dll").NewProc("NtQuerySystemInformation")
)

// loadWarbird maps the PlayReady module into this process and resolves the call gate, returning
// the image base. The module must stay mapped for the life of the process.
func loadWarbird() (base uintptr, err error) {
   base, err = wbLoad(dllPath)
   if err != nil {
      return 0, fmt.Errorf("loading %s: %w", dllPath, err)
   }
   // Resolve now: a Find failure inside mustFind panics, and a panic at the call site would
   // look like a fault in the descriptor's code.
   if err := wbNtQuery.Find(); err != nil {
      return 0, fmt.Errorf("NtQuerySystemInformation: %w", err)
   }
   return base, nil
}

// pfDLL returns the module's bytes and hex digest from one read, so the bytes hashed and the
// image loaded are provably the same.
func pfDLL() ([]byte, string, error) {
   fb, err := os.ReadFile(dllPath)
   if err != nil {
      return nil, "", err
   }
   sum := sha256.Sum256(fb)
   return fb, hex.EncodeToString(sum[:]), nil
}

// pfSave writes the profile indented: it is small, and "which build is cached, and how far did
// it get" is worth being able to read.
func pfSave(p *dllProfile) error {
   blob, err := json.MarshalIndent(p, "", "  ")
   if err != nil {
      return err
   }
   return os.WriteFile(profilePath, append(blob, '\n'), 0o644)
}

// statusOK reports whether the routine's status dword is zero. See the file header for why this
// and not NTSTATUS is the rejection signal.
func statusOK(b []byte) bool {
   return len(b) >= 4 && b[0]|b[1]|b[2]|b[3] == 0
}

// wbFree releases one reference taken by wbLoad. The error is returned rather than swallowed:
// -2 reloads the module once per heap block.
func wbFree(h uintptr) error {
   return syscall.FreeLibrary(syscall.Handle(h))
}

// wbLoad maps a module into this process and returns its base address.
func wbLoad(path string) (uintptr, error) {
   h, err := syscall.LoadLibrary(path)
   if err != nil {
      return 0, err
   }
   return uintptr(h), nil
}

// wbMemAt reinterprets an address the OS handed us as an integer. The direct form
// unsafe.Pointer(u) is rejected by vet's unsafeptr check, which cannot see that these integers
// are mapped addresses; unsafe.Add is the identity and vet accepts it. The pointer never
// escapes: every caller copies immediately.
func wbMemAt(u uintptr) unsafe.Pointer {
   return unsafe.Add(unsafe.Pointer(nil), u)
}

// wbPatch copies buf to base+rva, flipping the containing pages to RWX for the copy and
// restoring the previous protection afterwards.
//
// The restore is part of the operation, not cleanup: a page left writable is a page the kernel
// refuses to take a descriptor from (0xc000000d), so a failed restore is a failed patch.
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

// wbVEH installs a first-chance handler that reports the fault and exits. A false return means
// no handler was installed, and the caller must treat that as fatal: with no handler every
// fault is a plain process death with no output at all.
//
// THE os.Exit BELOW IS DELIBERATE AND IS THE PROGRAM'S ONLY ONE OUTSIDE main. The callback is
// invoked by Windows' exception dispatcher, not by Go code, so there is no caller to return a
// code to and no stack of ours to unwind: it cannot return an error (the signature belongs to
// the OS), cannot panic (a panic in a NewCallback trampoline is a fatal runtime abort that would
// replace the fault row with a crash dump), cannot CONTINUE_SEARCH (the fault would kill the
// process anyway) and cannot CONTINUE_EXECUTION (the faulting instruction would retry forever).
func wbVEH(base uintptr) bool {
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

      emit(childRow{Kind: "fault", Msg: fmt.Sprintf(
         "code=0x%08x addr=0x%016x off=%+#x module=%s bytes=%s",
         ep.Record.Code, ep.Record.Address,
         int64(ep.Record.Address)-int64(base), mod, raw)})
      os.Exit(3)
      return 0
   })
   h, _, _ := wbAddVEH.Call(1, cb)
   return h != 0
}

// pfLoad returns the profile for sha, or an empty one when the file is missing, unreadable, or
// written for a different build. Only the DLL-phase steps call it: they are about to fill in a
// section, so discarding a stale file is free.
func pfLoad(sha string) *dllProfile {
   if raw, err := os.ReadFile(profilePath); err == nil {
      var p dllProfile
      if json.Unmarshal(raw, &p) == nil && p.DLLSHA256 == sha {
         return &p
      }
   }
   return &dllProfile{DLLSHA256: sha}
}

// excPointers and excRecord are EXCEPTION_POINTERS and the head of EXCEPTION_RECORD. Nothing
// past ExceptionAddress is dereferenced.
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

// op3Func is one op=3 call: descriptor RVA, argument-block length, key size, status buffer, key
// buffer, output buffer, and the optional second size dword.
type op3Func func(descRVA, ln, keySize uint32, status, kb, out []byte, size2 *uint32) uint32

// op3Call returns the one implementation of WbHeapExecuteCall:
//
//   +0x00  op = 3
//   +0x08  descriptor address
//   +0x10  -> status dword   (routine's +0x00)
//   +0x18  -> 32-byte key    (routine's +0x08)
//   +0x20  u32 key size      (routine's +0x10)
//   +0x24  -> output buffer  (routine's +0x14)
//   +0x2C  u32 second size   (stage 2 only)
//
// Built bytewise, not as a struct: +0x24 is not 8-byte aligned, so Go would insert four bytes
// of padding and move the output pointer to +0x28, where the routine never looks.
//
// The three buffers reach the kernel only as uintptr values stored inside a, which the GC cannot
// follow: a slice kept alive by the call itself is not enough, because nothing points at its
// array any more. The KeepAlives are what hold them across the call.
func op3Call(base uintptr) op3Func {
   return func(descRVA, ln, keySize uint32, status, kb, out []byte, size2 *uint32) uint32 {
      var a [0x40]byte
      binary.LittleEndian.PutUint64(a[0x00:], 3)
      binary.LittleEndian.PutUint64(a[0x08:], uint64(base)+uint64(descRVA))
      binary.LittleEndian.PutUint64(a[0x10:], uint64(uintptr(unsafe.Pointer(&status[0]))))
      binary.LittleEndian.PutUint64(a[0x18:], uint64(uintptr(unsafe.Pointer(&kb[0]))))
      binary.LittleEndian.PutUint32(a[0x20:], keySize)
      binary.LittleEndian.PutUint64(a[0x24:], uint64(uintptr(unsafe.Pointer(&out[0]))))
      if size2 != nil {
         binary.LittleEndian.PutUint32(a[0x2C:], *size2)
      }
      r, _, _ := wbNtQuery.Call(0xB9, uintptr(unsafe.Pointer(&a[0])), uintptr(ln), 0)
      runtime.KeepAlive(status)
      runtime.KeepAlive(kb)
      runtime.KeepAlive(out)
      return uint32(r)
   }
}

// kernel.go end
