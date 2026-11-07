// 2-decrypt-img.go begin
//go:build windows

// =============================================================================
//
// Stage 2 of the chain: decrypt the Warbird-protected code and tables in
// Windows.Media.Protection.PlayReady.dll into a flat, plaintext image.
//
// WHY THIS EXISTS
//   PlayReady keeps the interesting parts of the library — the license blob
//   parser, the ECC key handling, the per-nibble bijection subtables — as
//   Warbird-encrypted blocks. The decryption keys live in the kernel and are
//   never exported, but the kernel will decrypt a block on request for any
//   descriptor whose embedded SHA-256 validates. So the image is decrypted
//   block by descriptor rather than by recovering a key.
//
//   Two different descriptor kinds need two different treatment:
//     - segment descriptors (?g_Encry, sizes other than 0xF0) each list one or
//       more RVA ranges. All of them can be decrypted in a single loaded image.
//     - heap-exec descriptors (size 0xF0) describe a single code block, and the
//       kernel only honours the FIRST such decrypt per loaded image. Each block
//       therefore needs its own fresh LoadLibraryW.
//
// PIPELINE
//   make-oracle      ->  testdata/oracle/key_NN.pub, testdata/oracle/lic_NN.blob
//   2-decrypt-img    ->  testdata/wbtool_img.bin              (this program)
//   3-derive-map     ->  testdata/oracle_map.json
//   4-derive-plain   ->  testdata/extracted.enc.plain
//
// INPUT
//   Windows.Media.Protection.PlayReady.dll, read directly from System32.
//   Nothing about this build is assumed: descriptor locations, counts, sizes,
//   the sacrificial slot and its relocation data are all discovered at runtime.
//
// OUTPUT   (both written under testdata/)
//   testdata/wbtool_img.bin   SizeOfImage bytes, laid out so RVA == file offset.
//                             Consumed by IMG in 3-derive-map and 4-derive-plain.
//   testdata/decrypt_img.txt  log: descriptor counts, per-block results, sample
//                             bytes.
//
// ACCEPTANCE CHECK
//   This stage cannot judge itself, because every address and every count is
//   per-build. What it must report is:
//       descriptors <n>  segments <n>  heap-exec <n>      (informational)
//       slot 0x<...>  relocs 0x<...>/<n>                  (resolved, not hardcoded)
//       segment descriptors <n> ok <n>                    (all must succeed)
//       heap-exec <n>  changed <n>  unchanged <n>  error 0
//   The real proof is 4-derive-plain printing pubkey MATCH: that requires the
//   stage routines to be real code, the blocks they call to be decrypted, and the
//   live bijection set to be intact. It is the only version-independent check.
//
// DO NOT COMPARE THE FILE HASH BETWEEN RUNS
//   Every LoadLibraryW bakes the current process load base into IAT slots and
//   relocated fields, so no two decrypted images hash alike even though they are
//   functionally identical. The hash in the log is a per-run identifier only.
//
// KNOWN PITFALLS
//   - Descriptor size cap must stay at 0x200000. The two largest descriptors on
//     the recorded build are 0x829c and 0x3cac; a 0x2000 cap silently skips them,
//     which loses the gap blocks 0x334290..0x3370ef and makes 4-derive-plain
//     execute ciphertext.
//   - Segment descriptors must be decrypted per descriptor, not per deduped RVA.
//     Descriptor span lists overlap; deduping by RVA drops later/larger spans
//     (7818 spans instead of 7937) and corrupts the downstream scalar.
//   - The sacrificial descriptor page's original protection must be restored
//     before the WB call, or the kernel rejects the descriptor with 0xc000000d.
//
// BUILD
//   GOOS=windows GOARCH=amd64 go build -o 2-decrypt-img.exe 2-decrypt-img.go
//   (requires golang.org/x/sys/windows)
// =============================================================================

package main

import (
   "bytes"
   "crypto/sha256"
   "encoding/binary"
   "fmt"
   "os"
   "path/filepath"
   "strconv"
   "strings"
   "unsafe"

   "golang.org/x/sys/windows"
)

// --- inputs / outputs --------------------------------------------------------

const (
   // input: read straight out of System32, never a copy
   dllPath = `C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll`
   // every artefact is written here
   dataDir = "testdata"

   // PAGE_EXECUTE_READWRITE
   rwx = 0x40
)

var (
   outPath = filepath.Join(dataDir, "wbtool_img.bin")  // consumed by 3- and 4-
   logPath = filepath.Join(dataDir, "decrypt_img.txt") // log only

   logLines []string

   ntdll                        = windows.NewLazySystemDLL("ntdll.dll")
   procNtQuerySystemInformation = ntdll.NewProc("NtQuerySystemInformation")
)

// =============================================================================
// Kernel call plumbing.
//
// NtQuerySystemInformation(0xB9) is the Warbird syscall. op=1 is "segment
// decrypt": the kernel decodes the descriptor, validates its digest, and
// decrypts [rva, rva+size) in the loaded image at `base`.
// =============================================================================

// call issues op=1 (segment decrypt) for the descriptor at `sac` inside `base`.
// NTSTATUS comes back in RAX, so r1 is the whole answer; only the low 32 bits
// are the status.
func call(base, sac, rel, num uintptr) uint32 {
   var a [0x30]byte
   binary.LittleEndian.PutUint64(a[0x00:], 1)                // op = 1, segment decrypt
   binary.LittleEndian.PutUint64(a[0x08:], uint64(sac))      // descriptor address
   binary.LittleEndian.PutUint64(a[0x10:], uint64(base))     // image base
   binary.LittleEndian.PutUint64(a[0x18:], uint64(base))     // image base
   binary.LittleEndian.PutUint64(a[0x20:], uint64(base+rel)) // relocations
   binary.LittleEndian.PutUint64(a[0x28:], uint64(num))      // relocation count

   r1, _, _ := procNtQuerySystemInformation.Call(
      0xB9,
      uintptr(unsafe.Pointer(&a[0])),
      0x30,
      0,
   )
   return uint32(r1)
}

// commas renders 1234567 as "1,234,567".
func commas(n int) string {
   neg := n < 0
   if neg {
      n = -n
   }
   s := strconv.Itoa(n)
   var b strings.Builder
   for i, c := range s {
      if i > 0 && (len(s)-i)%3 == 0 {
         b.WriteByte(',')
      }
      b.WriteRune(c)
   }
   if neg {
      return "-" + b.String()
   }
   return b.String()
}

func finish(msg string, code int) {
   if msg != "" {
      logln(msg)
   }
   _ = os.WriteFile(logPath, []byte(strings.Join(logLines, "\n")+"\n"), 0o644)
   os.Exit(code)
}

// =============================================================================
// Logging. Every line is buffered and printed; finish() writes the buffer, so
// the log survives an early exit.
// =============================================================================

func logf(format string, a ...any) {
   s := fmt.Sprintf(format, a...)
   logLines = append(logLines, s)
   fmt.Println(s) // Go's stdout is unbuffered, so no explicit flush needed
}

func logln(s string) { logf("%s", s) }

// =============================================================================

func main() {
   _ = os.MkdirAll(dataDir, 0o755)

   // =========================================================================
   // Descriptor discovery, offline from the file.
   //
   // A Warbird descriptor is a 0x20-byte SHA-256 digest followed by a body; the
   // digest covers [0x20, size) where size is the dword at +0x20. This validates
   // every candidate structurally, so no external tool is needed to enumerate
   // them.
   // =========================================================================
   f, err := os.ReadFile(dllPath)
   if err != nil {
      finish("FATAL: cannot read "+dllPath+": "+err.Error(), 1)
   }

   lf := int(u32(f, 0x3C))     // e_lfanew
   nsec := int(u16(f, lf+6))   // NumberOfSections
   optsz := int(u16(f, lf+20)) // SizeOfOptionalHeader
   sizeImg := u32(f, lf+24+56) // SizeOfImage

   p := lf + 24 + optsz
   secs := make([]section, 0, nsec)
   for i := 0; i < nsec; i++ {
      secs = append(secs, section{
         va:      u32(f, p+12), // VirtualAddress
         rawSize: u32(f, p+16), // SizeOfRawData
         rawPtr:  u32(f, p+20), // PointerToRawData
      })
      p += 40
   }

   // segs  : ?g_Encry blocks
   // heaps : 0xF0 heap-exec blocks
   var segs []seg
   var heaps []heap

   for _, s := range secs {
      start := int(s.rawPtr)
      end := start + int(s.rawSize)
      if end > len(f) {
         end = len(f) // clamp to the bytes actually present
      }
      if start >= len(f) {
         continue
      }
      b := f[start:end]

      for off := 0; off < len(b)-0x40; off += 4 {
         size := u32(b, off+0x20)
         // 0x200000, not 0x2000: the two largest descriptors on the recorded
         // build are 0x829c and 0x3cac bytes. A 0x2000 cap silently skips them,
         // which loses the gap blocks 0x334290..0x3370ef and makes
         // 4-derive-plain fault. Do not lower it.
         if size < 0x40 || size > 0x200000 || off+int(size) > len(b) {
            continue
         }
         sum := sha256.Sum256(b[off+0x20 : off+int(size)])
         if !bytes.Equal(sum[:], b[off:off+32]) {
            continue
         }

         descVA := s.va + uint32(off)
         fileOff := start + off

         if size == 0xF0 {
            // heap-exec descriptor: codeRVA at +0x34, codeLen at +0x38, both
            // masked with 0x0FFFFFFF (top nibble is a flag)
            rva := u32(b, off+0x34) & 0x0FFFFFFF
            sz := u32(b, off+0x38) & 0x0FFFFFFF
            heaps = append(heaps, heap{descVA: descVA, fileOff: fileOff, codeRVA: rva, codeSize: sz})
         } else {
            segs = append(segs, seg{descVA: descVA, fileOff: fileOff, size: size})
         }
      }
   }

   if len(segs) == 0 {
      finish("FATAL: no segment descriptors found", 1)
   }

   // --- Warbird calling convention constants --------------------------------
   // SLOT / RELOCS / NUM all vary between DLL builds, so they are read from a
   // real segment descriptor instead of being hardcoded. segs[0] is used as the
   // sacrificial slot because a genuine descriptor already carries its own
   // self-address at +0x28, which the kernel validates; a fabricated slot
   // elsewhere would have to be told its own RVA. On the recorded build this
   // resolves to SLOT 0x6d8000, RELOCS 0x943770, NUM 20888.
   //
   // The heap-exec pass overwrites this slot with a synthetic descriptor so the
   // kernel will decrypt an arbitrary RVA; the segment pass has already finished
   // by then, so reusing one of its descriptors is safe.
   slot := segs[0].descVA
   relocs := u32(f, segs[0].fileOff+0x2C)
   num := u32(f, segs[0].fileOff+0x30)

   origSum := sha256.Sum256(f)

   logf("dll     %s", dllPath)
   logf("sha256  %x", origSum)
   logf("image   0x%x (%s bytes)", sizeImg, commas(int(sizeImg)))
   logf("descriptors %d  segments %d  heap-exec %d", len(segs)+len(heaps), len(segs), len(heaps))
   logf("slot    0x%x  relocs 0x%x/%d", slot, relocs, num)
   logln("")

   // =========================================================================
   // Segment pass: ONE loaded image, op=1 against every real segment descriptor.
   //
   // Per-descriptor (not per-deduped-RVA) is essential: descriptors overlap, and
   // deduping by RVA drops the later/larger spans. That mistake produced 7818
   // spans instead of 7937 and a wrong downstream scalar.
   // =========================================================================
   base, err := windows.LoadLibrary(dllPath)
   if err != nil {
      finish("FATAL: LoadLibraryW failed: "+err.Error(), 1)
   }

   ok := 0
   for _, s := range segs {
      rel := u32(f, s.fileOff+0x2C) // this descriptor's own relocations
      n := u32(f, s.fileOff+0x30)
      if call(uintptr(base), uintptr(base)+uintptr(s.descVA), uintptr(rel), uintptr(n)) == 0 {
         ok++
      }
   }
   logf("segment descriptors %d ok %d", len(segs), ok)

   img := readMem(uintptr(base), int(sizeImg)) // harvest the whole image
   _ = windows.FreeLibrary(base)
   logln("")

   // =========================================================================
   // Heap-exec pass: ONE FRESH IMAGE PER BLOCK.
   //
   // The kernel only honours the first heap-exec decrypt per loaded image, so
   // the library must be reloaded for every block. Each iteration:
   //   - build a synthetic descriptor for (rva, size) using this block's crypto
   //     params (copied from the block's own descriptor body at +0x40..+0xF0)
   //   - write it over the sacrificial slot, then RESTORE THE SLOT'S ORIGINAL
   //     PAGE PROTECTION before the syscall (the kernel rejects a descriptor
   //     living on a writable page with 0xc000000d)
   //   - decrypt, read back, free
   // =========================================================================

   // decryptBlock returns (rc, plaintext, protFailed). protFailed reports that
   // VirtualProtect could not make the slot writable, so the block was skipped.
   decryptBlock := func(h heap) (rc uint32, got []byte, protFailed bool) {
      lib, err := windows.LoadLibrary(dllPath)
      if err != nil {
         finish(fmt.Sprintf("FATAL: LoadLibraryW failed at heap block 0x%x: %v", h.codeRVA, err), 1)
      }
      defer func() { _ = windows.FreeLibrary(lib) }()

      sac := uintptr(lib) + uintptr(slot)
      var oldProt uint32
      if err := windows.VirtualProtect(sac, 0x1000, rwx, &oldProt); err != nil {
         return 0, nil, true
      }

      hdr := readMem(sac, 0x40)
      params := f[h.fileOff+0x40 : h.fileOff+0xF0] // this block's own crypto params
      writeMem(sac, makeDesc(hdr, params, h.codeRVA, h.codeSize))

      var dummy uint32
      // restore BEFORE syscall
      _ = windows.VirtualProtect(sac, 0x1000, oldProt, &dummy)

      rc = call(uintptr(lib), sac, uintptr(relocs), uintptr(num))
      got = readMem(uintptr(lib)+uintptr(h.codeRVA), int(h.codeSize))
      return rc, got, false
   }

   done, same, errCount := 0, 0, 0
   type unchanged struct {
      rva, size, owner uint32
   }
   var fails []unchanged

   for i, h := range heaps {
      idx := i + 1

      if h.codeRVA == 0 || h.codeSize == 0 ||
         uint64(h.codeRVA)+uint64(h.codeSize) > uint64(sizeImg) {
         errCount++
         continue
      }
      before := append([]byte(nil), img[h.codeRVA:h.codeRVA+h.codeSize]...)

      rc, got, protFailed := decryptBlock(h)
      if protFailed {
         errCount++
         continue
      }

      switch {
      case rc == 0 && len(got) == int(h.codeSize) && !bytes.Equal(got, before):
         copy(img[h.codeRVA:], got)
         done++
      case rc == 0:
         // was already plaintext (e.g. .data entries) - not an error
         same++
         if len(fails) < 12 {
            fails = append(fails, unchanged{h.codeRVA, h.codeSize, h.descVA})
         }
      default:
         errCount++
      }

      if idx%200 == 0 {
         logf("  %d/%d  changed %d  same %d  err %d", idx, len(heaps), done, same, errCount)
      }
   }

   logln("")
   logf("heap-exec %d  changed %d  unchanged %d  error %d", len(heaps), done, same, errCount)
   for _, u := range fails {
      logf("  unchanged 0x%06x+0x%x owner 0x%x", u.rva, u.size, u.owner)
   }
   logln("")

   if err := os.WriteFile(outPath, img, 0o644); err != nil {
      finish("FATAL: cannot write "+outPath+": "+err.Error(), 1)
   }

   // --- build signature -----------------------------------------------------
   // Deliberately no hardcoded probe addresses: they are per-build. Instead dump
   // the first bytes of the first heap-exec block and of the largest segment
   // span, both chosen at runtime, so the log is still useful for eyeballing
   // real code.
   dump := func(tag string, rva uint32, n int) {
      lo := int(rva)
      hi := lo + n
      if hi > len(img) {
         hi = len(img)
      }
      if lo > len(img) {
         lo = len(img)
      }
      logf("  %s 0x%06x %x", tag, rva, img[lo:hi])
   }

   if len(heaps) > 0 {
      dump("first heap-exec", heaps[0].codeRVA, 16)
   }
   if len(segs) > 0 {
      big := segs[0]
      for _, s := range segs[1:] {
         if s.size > big.size {
            big = s
         }
      }
      dump("largest segment", big.descVA, 16)
   }

   logln("")
   logf("written %s  (%s bytes)", outPath, commas(len(img)))
   imgSum := sha256.Sum256(img)
   logf("sha256   %x", imgSum)
   finish("", 0)
}

// makeDesc builds a synthetic 1-entry segment descriptor:
//
//   [0x00..0x20)  sha256 over the body
//   [0x20]        total size (0x100)
//   [0x40..0xF0)  crypto params copied from a real descriptor
//   [0xF0]        entry count (1)
//   [0xF4]        entry flags
//   [0xF8]        entry rva
//   [0xFC]        entry size
//
// hdr is the first 0x40 bytes of the sacrificial slot, reused so the header
// shape matches what the kernel expects for this build.
func makeDesc(hdr, params []byte, rva, size uint32) []byte {
   buf := make([]byte, 0x100)
   copy(buf[0x00:0x40], hdr)
   copy(buf[0x40:], params) // params is 0xB0 bytes -> lands at [0x40..0xF0)

   binary.LittleEndian.PutUint32(buf[0x20:], 0x100) // descriptor total size
   binary.LittleEndian.PutUint32(buf[0xF0:], 1)     // 1 entry
   binary.LittleEndian.PutUint32(buf[0xF4:], 0x30C) // flags
   binary.LittleEndian.PutUint32(buf[0xF8:], rva)
   binary.LittleEndian.PutUint32(buf[0xFC:], size)

   sum := sha256.Sum256(buf[0x20:0x100])
   copy(buf[0x00:0x20], sum[:])
   return buf
}

// =============================================================================
// Raw memory access into the process we are running in.
//
// `base` is an address handed back by LoadLibraryW, not a Go pointer, so the GC
// neither knows nor needs to know about it. vet's unsafeptr analyzer rejects
// unsafe.Pointer(uintptr) outright and cannot tell that this uintptr is foreign,
// so the conversion is routed through unsafe.Add, which is the identity on the
// address and produces exactly the same pointer.
//
// The pointer never escapes: both helpers copy immediately, so the slice header
// holding the foreign address dies on the stack frame.
// =============================================================================

func ptrAt(u uintptr) unsafe.Pointer {
   return unsafe.Add(unsafe.Pointer(nil), u)
}

func readMem(base uintptr, n int) []byte {
   out := make([]byte, n)
   if n == 0 {
      return out
   }
   copy(out, unsafe.Slice((*byte)(ptrAt(base)), n))
   return out
}

// =============================================================================
// Little-endian readers over a byte slice. Panic on out-of-range.
// =============================================================================

func u16(b []byte, off int) uint16 { return binary.LittleEndian.Uint16(b[off:]) }
func u32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }

func writeMem(dst uintptr, src []byte) {
   if len(src) == 0 {
      return
   }
   copy(unsafe.Slice((*byte)(ptrAt(dst)), len(src)), src)
}

// heap is a 0xF0 heap-exec descriptor: one code block, one fresh image each.
type heap struct {
   descVA   uint32
   fileOff  int
   codeRVA  uint32
   codeSize uint32
}

// =============================================================================
// Descriptor records
// =============================================================================

type section struct {
   va      uint32 // VirtualAddress
   rawSize uint32 // SizeOfRawData
   rawPtr  uint32 // PointerToRawData
}

// seg is a ?g_Encry segment descriptor: one loaded image, op=1, all of them.
type seg struct {
   descVA  uint32 // RVA of the descriptor inside the image
   fileOff int    // file offset of the descriptor
   size    uint32
}

// 2-decrypt-img.go end
