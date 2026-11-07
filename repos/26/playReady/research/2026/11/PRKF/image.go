// image.go begin
//go:build windows

// =============================================================================
//
// prkf -5: decrypt the Warbird-protected code and tables in the PlayReady DLL
// into a flat, plaintext image.
//
// WHY THIS EXISTS
//   PlayReady keeps the interesting parts of the library - the license blob
//   parser, the ECC key handling, the per-nibble bijection subtables - as
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
// The descriptor format and the census that finds descriptors are in
// warbird.go; this file is the op=1 call and the two passes over them.
//
// PIPELINE
//   prkf -4  ->  oracle/key_NN.pub, oracle/lic_NN.blob
//   prkf -5  ->  wbtool_img.bin              (this step)
//   prkf -6  ->  oracle_map.json
//   prkf -7  ->  extracted.enc.plain
//
// INPUT
//   dllPath, read directly from System32. Nothing about this build is assumed:
//   descriptor locations, counts, sizes, the sacrificial slot and its
//   relocation data are all discovered at runtime.
//
// OUTPUT
//   imgPath    SizeOfImage bytes, laid out so RVA == file offset. Consumed by
//              -6 and -7.
//   imgLogPath descriptor counts, per-block results, sample bytes.
//
// USAGE
//   prkf -5
//
//   No flags of its own. Both output paths and the DLL are manifest entries in
//   main.go.
//
// ACCEPTANCE CHECK
//   This step cannot judge itself, because every address and every count is
//   per-build. What it must report is:
//       descriptors <n>  segments <n>  heap-exec <n>      (informational)
//       slot 0x<...>  relocs 0x<...>/<n>                  (resolved, not hardcoded)
//       segment descriptors <n> ok <n>                    (all must succeed)
//       heap-exec <n>  changed <n>  unchanged <n>  error 0
//   The real proof is -7 printing pubkey MATCH: that requires the stage routines
//   to be real code, the blocks they call to be decrypted, and the live
//   bijection set to be intact. It is the only version-independent check.
//
// DO NOT COMPARE THE FILE HASH BETWEEN RUNS
//   Every LoadLibraryW bakes the current process load base into IAT slots and
//   relocated fields, so no two decrypted images hash alike even though they are
//   functionally identical. The hash in the log is a per-run identifier only.
//
// KNOWN PITFALLS
//   - Descriptor size cap must stay at 0x200000; see scanDescs in warbird.go.
//   - Segment descriptors must be decrypted per descriptor, not per deduped RVA.
//     Descriptor span lists overlap; deduping by RVA drops later/larger spans
//     (7818 spans instead of 7937) and corrupts the downstream scalar.
//   - The sacrificial descriptor page's original protection must be restored
//     before the WB call, or the kernel rejects the descriptor with 0xc000000d.
//
// BUILD
//   GOOS=windows GOARCH=amd64 go build -o prkf.exe .
//   (requires golang.org/x/sys/windows)
// =============================================================================

package main

import (
   "bytes"
   "crypto/sha256"
   "encoding/binary"
   "fmt"
   "os"
   "strconv"
   "strings"
   "unsafe"

   "golang.org/x/sys/windows"
)

// PAGE_EXECUTE_READWRITE
const diRWX = 0x40

var (
   diLogLines []string

   diNTDLL                        = windows.NewLazySystemDLL("ntdll.dll")
   diProcNtQuerySystemInformation = diNTDLL.NewProc("NtQuerySystemInformation")
)

// =============================================================================
// Kernel call plumbing.
//
// NtQuerySystemInformation(0xB9) is the Warbird syscall. op=1 is "segment
// decrypt": the kernel decodes the descriptor, validates its digest, and
// decrypts [rva, rva+size) in the loaded image at `base`.
// =============================================================================

// diCall issues op=1 (segment decrypt) for the descriptor at `sac` inside
// `base`. NTSTATUS comes back in RAX, so r1 is the whole answer; only the low
// 32 bits are the status.
func diCall(base, sac, rel, num uintptr) uint32 {
   var a [0x30]byte
   binary.LittleEndian.PutUint64(a[0x00:], 1)                // op = 1, segment decrypt
   binary.LittleEndian.PutUint64(a[0x08:], uint64(sac))      // descriptor address
   binary.LittleEndian.PutUint64(a[0x10:], uint64(base))     // image base
   binary.LittleEndian.PutUint64(a[0x18:], uint64(base))     // image base
   binary.LittleEndian.PutUint64(a[0x20:], uint64(base+rel)) // relocations
   binary.LittleEndian.PutUint64(a[0x28:], uint64(num))      // relocation count

   r1, _, _ := diProcNtQuerySystemInformation.Call(
      0xB9,
      uintptr(unsafe.Pointer(&a[0])),
      0x30,
      0,
   )
   return uint32(r1)
}

// diCommas renders 1234567 as "1,234,567".
func diCommas(n int) string {
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

func diFinish(msg string, code int) {
   if msg != "" {
      diLogln(msg)
   }
   _ = os.WriteFile(imgLogPath, []byte(strings.Join(diLogLines, "\n")+"\n"), 0o644)
   os.Exit(code)
}

// =============================================================================
// Logging. Every line is buffered and printed; diFinish() writes the buffer, so
// the log survives an early exit.
// =============================================================================

func diLogf(format string, a ...any) {
   s := fmt.Sprintf(format, a...)
   diLogLines = append(diLogLines, s)
   fmt.Println(s) // Go's stdout is unbuffered, so no explicit flush needed
}

func diLogln(s string) {
   diLogf("%s", s)
}

// diMakeDesc builds a synthetic 1-entry segment descriptor:
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
func diMakeDesc(hdr, params []byte, rva, size uint32) []byte {
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

func diPtrAt(u uintptr) unsafe.Pointer {
   return unsafe.Add(unsafe.Pointer(nil), u)
}

func diReadMem(base uintptr, n int) []byte {
   out := make([]byte, n)
   if n == 0 {
      return out
   }
   copy(out, unsafe.Slice((*byte)(diPtrAt(base)), n))
   return out
}

func diWriteMem(dst uintptr, src []byte) {
   if len(src) == 0 {
      return
   }
   copy(unsafe.Slice((*byte)(diPtrAt(dst)), len(src)), src)
}

// =============================================================================

func stageDecryptImg() int {
   if err := os.MkdirAll(outDir, 0o755); err != nil {
      diFinish("FATAL: cannot create "+outDir+": "+err.Error(), 1)
   }

   // =========================================================================
   // Descriptor discovery, offline from the file.
   //
   // A Warbird descriptor is a 0x20-byte SHA-256 digest followed by a body; the
   // digest covers [0x20, size) where size is the dword at +0x20. This validates
   // every candidate structurally, so no external tool is needed to enumerate
   // them. The scan itself is shared: see scanDescs in warbird.go.
   // =========================================================================
   f, err := os.ReadFile(dllPath)
   if err != nil {
      diFinish("FATAL: cannot read "+dllPath+": "+err.Error(), 1)
   }

   sizeImg, secs := peSections(f)

   var segs, heaps []imgDesc
   for _, d := range scanDescs(f, secs) {
      if d.heap() {
         heaps = append(heaps, d)
      } else {
         segs = append(segs, d)
      }
   }

   if len(segs) == 0 {
      diFinish("FATAL: no segment descriptors found", 1)
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
   slot := segs[0].va
   relocs := le32(f, int(segs[0].off)+0x2C)
   num := le32(f, int(segs[0].off)+0x30)

   origSum := sha256.Sum256(f)

   diLogf("dll     %s", dllPath)
   diLogf("sha256  %x", origSum)
   diLogf("image   0x%x (%s bytes)", sizeImg, diCommas(int(sizeImg)))
   diLogf("descriptors %d  segments %d  heap-exec %d", len(segs)+len(heaps), len(segs), len(heaps))
   diLogf("slot    0x%x  relocs 0x%x/%d", slot, relocs, num)
   diLogln("")

   // =========================================================================
   // Segment pass: ONE loaded image, op=1 against every real segment descriptor.
   //
   // Per-descriptor (not per-deduped-RVA) is essential: descriptors overlap, and
   // deduping by RVA drops the later/larger spans. That mistake produced 7818
   // spans instead of 7937 and a wrong downstream scalar.
   // =========================================================================
   base, err := windows.LoadLibrary(dllPath)
   if err != nil {
      diFinish("FATAL: LoadLibraryW failed: "+err.Error(), 1)
   }

   ok := 0
   for _, s := range segs {
      rel := le32(f, int(s.off)+0x2C) // this descriptor's own relocations
      n := le32(f, int(s.off)+0x30)
      if diCall(uintptr(base), uintptr(base)+uintptr(s.va), uintptr(rel), uintptr(n)) == 0 {
         ok++
      }
   }
   diLogf("segment descriptors %d ok %d", len(segs), ok)

   img := diReadMem(uintptr(base), int(sizeImg)) // harvest the whole image
   _ = windows.FreeLibrary(base)
   diLogln("")

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
   decryptBlock := func(h imgDesc) (rc uint32, got []byte, protFailed bool) {
      lib, err := windows.LoadLibrary(dllPath)
      if err != nil {
         diFinish(fmt.Sprintf("FATAL: LoadLibraryW failed at heap block 0x%x: %v", h.rva, err), 1)
      }
      defer func() { _ = windows.FreeLibrary(lib) }()

      sac := uintptr(lib) + uintptr(slot)
      var oldProt uint32
      if err := windows.VirtualProtect(sac, 0x1000, diRWX, &oldProt); err != nil {
         return 0, nil, true
      }

      hdr := diReadMem(sac, 0x40)
      params := f[int(h.off)+0x40 : int(h.off)+0xF0] // this block's own crypto params
      diWriteMem(sac, diMakeDesc(hdr, params, h.rva, h.ln))

      var dummy uint32
      // restore BEFORE syscall
      _ = windows.VirtualProtect(sac, 0x1000, oldProt, &dummy)

      rc = diCall(uintptr(lib), sac, uintptr(relocs), uintptr(num))
      got = diReadMem(uintptr(lib)+uintptr(h.rva), int(h.ln))
      return rc, got, false
   }

   done, same, errCount := 0, 0, 0
   type unchanged struct {
      rva, size, owner uint32
   }
   var fails []unchanged

   for i, h := range heaps {
      idx := i + 1

      if h.rva == 0 || h.ln == 0 ||
         uint64(h.rva)+uint64(h.ln) > uint64(sizeImg) {
         errCount++
         continue
      }
      before := append([]byte(nil), img[h.rva:h.rva+h.ln]...)

      rc, got, protFailed := decryptBlock(h)
      if protFailed {
         errCount++
         continue
      }

      switch {
      case rc == 0 && len(got) == int(h.ln) && !bytes.Equal(got, before):
         copy(img[h.rva:], got)
         done++
      case rc == 0:
         // was already plaintext (e.g. .data entries) - not an error
         same++
         if len(fails) < 12 {
            fails = append(fails, unchanged{h.rva, h.ln, h.va})
         }
      default:
         errCount++
      }

      if idx%200 == 0 {
         diLogf("  %d/%d  changed %d  same %d  err %d", idx, len(heaps), done, same, errCount)
      }
   }

   diLogln("")
   diLogf("heap-exec %d  changed %d  unchanged %d  error %d", len(heaps), done, same, errCount)
   for _, u := range fails {
      diLogf("  unchanged 0x%06x+0x%x owner 0x%x", u.rva, u.size, u.owner)
   }
   diLogln("")

   if err := os.WriteFile(imgPath, img, 0o644); err != nil {
      diFinish("FATAL: cannot write "+imgPath+": "+err.Error(), 1)
   }

   // --- build signature -----------------------------------------------------
   // Deliberately no hardcoded probe addresses: they are per-build. Instead dump
   // the first bytes of the first heap-exec block and of the largest segment
   // descriptor, both chosen at runtime, so the log is still useful for
   // eyeballing real code.
   dump := func(tag string, rva uint32, n int) {
      lo := int(rva)
      hi := lo + n
      if hi > len(img) {
         hi = len(img)
      }
      if lo > len(img) {
         lo = len(img)
      }
      diLogf("  %s 0x%06x %x", tag, rva, img[lo:hi])
   }

   if len(heaps) > 0 {
      dump("first heap-exec", heaps[0].rva, 16)
   }
   if len(segs) > 0 {
      big := segs[0]
      for _, s := range segs[1:] {
         if s.size > big.size {
            big = s
         }
      }
      dump("largest segment", big.va, 16)
   }

   diLogln("")
   diLogf("written %s  (%s bytes)", imgPath, diCommas(len(img)))
   imgSum := sha256.Sum256(img)
   diLogf("sha256   %x", imgSum)
   diFinish("", 0)
   return 0
}

// image.go end
