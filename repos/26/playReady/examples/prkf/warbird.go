// warbird.go begin
//go:build windows

// The Warbird descriptor format, the PE census that finds descriptors in a DLL on
// disk, the span and block carving, and -2, the op=1 segment decrypt that turns
// the module into a flat image.
//
// # THE DESCRIPTOR FORMAT
//
// A Warbird descriptor is a 32-byte SHA-256 digest followed by a body, and the
// digest covers [0x20, size) where size is the u32 at +0x20, so every descriptor
// validates itself and none needs external symbol data to enumerate.
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
// A descriptor has THREE distinct addresses, and confusing them is the easiest bug
// here: its own address (`va`), desc_va (+0x28, what op=3 is handed and what a
// call targets) and code rva (+0x34, where the code lives). The census stores all
// three.
//
// # -2, THE SEGMENT DECRYPT
//
// PlayReady keeps the interesting parts of the library as Warbird-encrypted
// blocks. The keys live in the kernel and are never exported, but the kernel will
// decrypt a block on request for any descriptor whose embedded SHA-256 validates.
//
// Two kinds need two treatments:
//   - segment descriptors (?g_Encry, sizes other than 0xF0) each list one or more
//     RVA ranges; all of them decrypt in a single loaded image.
//   - heap-exec descriptors (size 0xF0) describe one code block, and the kernel
//     honours only the FIRST such decrypt per loaded image, so each block needs
//     its own fresh LoadLibraryW.
//
// DO NOT COMPARE THE IMAGE HASH BETWEEN RUNS. Every LoadLibraryW bakes the process
// load base into IAT slots and relocated fields, so no two decrypted images hash
// alike even though they are identical. That is why the profile is keyed by the
// DLL's digest and the image is cross-checked by length.
//
// KNOWN PITFALLS. The descriptor size cap must stay at 0x200000 (see scanDescs);
// segment descriptors must be decrypted per descriptor, not per deduped RVA, or the
// later/larger spans are lost; and the sacrificial page's protection must be
// restored before the WB call, or the kernel rejects it with 0xc000000d.
package main

import (
   "bytes"
   "cmp"
   "crypto/sha256"
   "encoding/binary"
   "fmt"
   "os"
   "slices"
   "strings"
   "unsafe"
)

// ------------------------------------------------------------- -2: op=1

// diCall issues op=1 (segment decrypt) for the descriptor at `sac` inside `base`.
// NTSTATUS comes back in RAX, so r1 is the whole answer; only the low 32 bits are
// the status.
func diCall(base, sac, rel, num uintptr) uint32 {
   var a [0x30]byte
   binary.LittleEndian.PutUint64(a[0x00:], 1)                // op = 1, segment decrypt
   binary.LittleEndian.PutUint64(a[0x08:], uint64(sac))      // descriptor address
   binary.LittleEndian.PutUint64(a[0x10:], uint64(base))     // image base
   binary.LittleEndian.PutUint64(a[0x18:], uint64(base))     // image base
   binary.LittleEndian.PutUint64(a[0x20:], uint64(base+rel)) // relocations
   binary.LittleEndian.PutUint64(a[0x28:], uint64(num))      // relocation count

   // wbNtQuery is the one NtQuerySystemInformation LazyProc in the program;
   // kernel.go owns it, so no step can resolve it differently.
   r1, _, _ := wbNtQuery.Call(0xB9, uintptr(unsafe.Pointer(&a[0])), 0x30, 0)
   return uint32(r1)
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
// hdr is the first 0x40 bytes of the sacrificial slot, reused so the header shape
// matches what the kernel expects for this build.
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

// diReadMem copies n bytes out of the process we are running in. The conversion is
// wbMemAt's, in kernel.go, so there is one statement in the program of why a
// uintptr becomes an unsafe.Pointer; the write direction is wbPatch, which owns
// the protection flip that must bracket it.
func diReadMem(base uintptr, n int) []byte {
   out := make([]byte, n)
   if n == 0 {
      return out
   }
   copy(out, unsafe.Slice((*byte)(wbMemAt(base)), n))
   return out
}

func le16(b []byte, o int) uint16 { return binary.LittleEndian.Uint16(b[o:]) }
func le32(b []byte, o int) uint32 { return binary.LittleEndian.Uint32(b[o:]) }

func stageDecryptImg() (code int) {
   // Logging. Every line is buffered and printed; the deferred flush below writes
   // the buffer on every return path, so the log survives an early exit without any
   // exit call here.
   var lines []string
   logf := func(format string, a ...any) {
      s := fmt.Sprintf(format, a...)
      lines = append(lines, s)
      fmt.Println(s) // Go's stdout is unbuffered, so no explicit flush needed
   }
   // fail records a fatal condition in the log and yields exit code 1. It does not
   // write the log or terminate: the deferred flush owns that, so no return path
   // can leave the log unwritten.
   fail := func(format string, a ...any) int {
      logf("FATAL: "+format, a...)
      return 1
   }
   defer func() {
      if err := os.WriteFile(imgLogPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
         fmt.Fprintf(os.Stderr, "prkf -2: %s: %v\n", imgLogPath, err)
         if code == 0 {
            code = 1
         }
      }
   }()

   if err := os.MkdirAll(outDir, 0o755); err != nil {
      return fail("cannot create %s: %v", outDir, err)
   }

   // Descriptor discovery, offline from the file. A Warbird descriptor is a
   // 0x20-byte SHA-256 digest followed by a body; the digest covers [0x20, size)
   // where size is the dword at +0x20. This validates every candidate structurally,
   // so no external tool is needed to enumerate them.
   f, err := os.ReadFile(dllPath)
   if err != nil {
      return fail("cannot read %s: %v", dllPath, err)
   }

   sizeImg, secs := peSections(f)
   segs, heaps := splitDescs(f, secs)
   if len(segs) == 0 {
      return fail("no segment descriptors found")
   }

   // --- Warbird calling convention constants --------------------------------
   // SLOT / RELOCS / NUM all vary between DLL builds, so they are read from a real
   // segment descriptor instead of being hardcoded. segs[0] is used as the
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

   sum := sha256.Sum256(f)
   shaHex := fmt.Sprintf("%x", sum)

   logf("dll     %s", dllPath)
   logf("sha256  %s", shaHex)
   logf("image   0x%x (%d bytes)", sizeImg, sizeImg)
   logf("descriptors %d  segments %d  heap-exec %d", len(segs)+len(heaps), len(segs), len(heaps))
   logf("slot    0x%x  relocs 0x%x/%d", slot, relocs, num)
   logf("")

   // Segment pass: ONE loaded image, op=1 against every real segment descriptor.
   // Per-descriptor (not per-deduped-RVA) is essential: descriptors overlap, and
   // deduping by RVA drops the later/larger spans. That mistake produced 7818
   // spans instead of 7937 and a wrong downstream scalar.
   base, err := wbLoad(dllPath)
   if err != nil {
      return fail("LoadLibraryW failed: %v", err)
   }

   ok := 0
   for _, s := range segs {
      rel := le32(f, int(s.off)+0x2C) // this descriptor's own relocations
      n := le32(f, int(s.off)+0x30)
      if diCall(base, base+uintptr(s.va), uintptr(rel), uintptr(n)) == 0 {
         ok++
      }
   }
   logf("segment descriptors %d ok %d", len(segs), ok)

   img := diReadMem(base, int(sizeImg)) // harvest the whole image
   if err := wbFree(base); err != nil {
      logf("warning: FreeLibrary after segment pass: %v", err)
   }
   logf("")

   // Heap-exec pass: ONE FRESH IMAGE PER BLOCK. The kernel only honours the first
   // heap-exec decrypt per loaded image, so the library must be reloaded for every
   // block. Each iteration builds a synthetic descriptor for (rva, size) from this
   // block's own crypto params (+0x40..+0xF0), writes it over the sacrificial slot,
   // restores the slot's original protection (the kernel rejects a descriptor on a
   // writable page with 0xc000000d), decrypts, reads back and frees.
   //
   // decryptBlock returns (rc, plaintext, protFailed, err). protFailed reports that
   // VirtualProtect could not make the slot writable OR could not restore it, so
   // the block was skipped. Both are charged here rather than to the block's code.
   // The write-and-restore pair is wbPatch, so there is one place where the restore
   // can be forgotten.
   decryptBlock := func(h imgDesc) (rc uint32, got []byte, protFailed bool, err error) {
      lib, err := wbLoad(dllPath)
      if err != nil {
         return 0, nil, false, fmt.Errorf("LoadLibraryW failed at heap block 0x%x: %w", h.rva, err)
      }
      defer func() {
         if ferr := wbFree(lib); ferr != nil {
            logf("  warning: FreeLibrary at heap block 0x%x: %v", h.rva, ferr)
         }
      }()

      sac := lib + uintptr(slot)
      hdr := diReadMem(sac, 0x40)
      params := f[int(h.off)+0x40 : int(h.off)+0xF0] // this block's own crypto params
      if !wbPatch(lib, slot, diMakeDesc(hdr, params, h.rva, h.ln)) {
         return 0, nil, true, nil
      }

      rc = diCall(lib, sac, uintptr(relocs), uintptr(num))
      got = diReadMem(lib+uintptr(h.rva), int(h.ln))
      return rc, got, false, nil
   }

   done, same, errCount := 0, 0, 0
   type unchanged struct {
      rva, size, owner uint32
   }
   var fails []unchanged

   for i, h := range heaps {
      idx := i + 1

      if h.rva == 0 || h.ln == 0 || uint64(h.rva)+uint64(h.ln) > uint64(sizeImg) {
         errCount++
         continue
      }
      before := append([]byte(nil), img[h.rva:h.rva+h.ln]...)

      rc, got, protFailed, err := decryptBlock(h)
      if err != nil {
         return fail("%v", err)
      }
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
         logf("  %d/%d  changed %d  same %d  err %d", idx, len(heaps), done, same, errCount)
      }
   }

   logf("")
   logf("heap-exec %d  changed %d  unchanged %d  error %d", len(heaps), done, same, errCount)
   for _, u := range fails {
      logf("  unchanged 0x%06x+0x%x owner 0x%x", u.rva, u.size, u.owner)
   }
   logf("")

   if err := os.WriteFile(imgPath, img, 0o644); err != nil {
      return fail("cannot write %s: %v", imgPath, err)
   }

   // --- the profile ---------------------------------------------------------
   // -2 establishes it: it is the first step that both knows the DLL's digest and
   // produces the artefact everything else is measured against.
   //
   // The census goes in here, not just SizeOfImage. scanDescs hashes several
   // gigabytes to find the descriptors, and every trial child needs the spans and
   // heap blocks it produces; recomputing them per child - and a fault costs a
   // child - was the entire cost of -4.
   //
   // A heap entry is {va, descVA, codeRVA, codeLen}. All four are needed: `va` is
   // the descriptor's own address, which identifies a candidate and is what op=3 is
   // handed; `descVA` is +0x28, which is what a call inside the image targets.
   //
   // pfLoad, not pfNew. Re-running -2 against the same build must not discard a map
   // and a stage pairing that are still valid.
   cen := &profileCensus{}
   for _, d := range segs {
      for _, sp := range segSpans(f, d, sizeImg) {
         cen.Spans = append(cen.Spans, [2]uint32{sp.rva, sp.size})
      }
   }
   for _, h := range heaps {
      cen.Heaps = append(cen.Heaps, [4]uint32{h.va, h.descVA, h.rva, h.ln})
   }

   p := pfLoad(shaHex)
   p.SizeOfImage = sizeImg
   p.Census = cen
   if err := pfSave(p); err != nil {
      return fail("cannot write %s: %v", profilePath, err)
   }
   logf("profile %s  dll %s  SizeOfImage 0x%x  spans %d  heap-exec %d",
      profilePath, shaHex[:16]+"...", sizeImg, len(cen.Spans), len(cen.Heaps))
   logf("")

   // --- build signature -----------------------------------------------------
   // Deliberately no hardcoded probe addresses: they are per-build. Instead dump
   // the first bytes of the first heap-exec block and of the largest segment
   // descriptor, both chosen at runtime, so the log is still useful for eyeballing
   // real code.
   dump := func(tag string, rva uint32, n int) {
      lo := min(int(rva), len(img))
      logf("  %s 0x%06x %x", tag, rva, img[lo:min(lo+n, len(img))])
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

   logf("")
   logf("written %s  (%d bytes)", imgPath, len(img))
   logf("sha256   %x", sha256.Sum256(img))
   return 0
}

// ------------------------------------------------------------- descriptors

// imgDesc is one digest-validated descriptor. va is its own address and is what
// identifies a candidate and what op=3 is handed; descVA is +0x28 and is what a
// call inside the image targets; rva and ln are the code block, meaningful only
// for heap-exec descriptors. off and size are the descriptor's file position.
type imgDesc struct {
   va     uint32
   off    uint32
   size   uint32
   descVA uint32
   rva    uint32
   ln     uint32
}

// scanDescs returns every digest-validated descriptor in the file, in the order
// the sections and their bytes appear.
//
// A candidate is accepted when its size field is plausible and the SHA-256 over
// [0x20, size) matches the digest that precedes it. Nothing else is checked: the
// digest is the signature, so a descriptor that passes is one the kernel will
// accept.
//
// THIS IS THE EXPENSIVE FUNCTION IN THE PROGRAM. It hashes every 4-byte offset
// whose size field lands in range, which on a 10 MB image is several gigabytes of
// SHA-256. It runs once, in -2, and the result is cached in the profile so trial
// children never pay it.
//
// The 0x200000 cap is deliberate and must not be lowered. The two largest
// descriptors on the recorded build are 0x829c and 0x3cac bytes; a 0x2000 cap
// silently skips them, which loses the gap blocks 0x334290..0x3370ef and makes -4
// execute ciphertext.
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

         // top nibble of desc_va and of both heap-exec fields is a flag; the rest
         // is an RVA
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
// order. -1, -2, -3, -4 and -7 all need exactly this split.
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

// heap reports whether this is a heap-exec descriptor. 0xF0 is the only size the
// kernel treats that way, and the size field is covered by the digest, so the test
// cannot be spoofed by a corrupt byte.
func (d imgDesc) heap() bool { return d.size == 0xF0 }

// imgInterval is a half-open RVA range: one heap-exec block, or a merged run.
type imgInterval struct{ lo, hi uint32 }

// heapIntervals turns heap-exec descriptors into the RVA ranges the kernel
// decrypts itself, ready for mergeIntervals.
func heapIntervals(heaps []imgDesc) []imgInterval {
   var ivs []imgInterval
   for _, h := range heaps {
      if h.ln != 0 {
         ivs = append(ivs, imgInterval{h.rva, h.rva + h.ln})
      }
   }
   return ivs
}

// mergeIntervals sorts and coalesces ranges, so carveRuns can binary-search them.
func mergeIntervals(ivs []imgInterval) []imgInterval {
   slices.SortFunc(ivs, func(a, b imgInterval) int { return cmp.Compare(a.lo, b.lo) })

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

   // Start at the last interval whose lo is at or below r. BinarySearchFunc
   // reports the first entry that is not less than the target, so an exact hit is
   // that entry and a miss leaves pos one past the last candidate.
   pos, found := slices.BinarySearchFunc(merged, r, func(m imgInterval, t uint32) int {
      return cmp.Compare(m.lo, t)
   })
   if !found {
      pos = max(pos-1, 0)
   }

   for _, m := range merged[pos:] {
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

// coalesceRuns sorts runs and merges the ones that touch. Every run is written from
// the same source image, so adjacent runs are equivalent to their union - and
// merging them turns thousands of VirtualProtect pairs into a few dozen.
func coalesceRuns(runs []imgRun) []imgRun {
   slices.SortFunc(runs, func(a, b imgRun) int { return cmp.Compare(a.start, b.start) })
   var out []imgRun
   for _, r := range runs {
      if n := len(out); n > 0 {
         end := uint64(out[n-1].start) + uint64(out[n-1].length)
         if uint64(r.start) <= end {
            hi := max(end, uint64(r.start)+uint64(r.length))
            out[n-1].length = uint32(hi - uint64(out[n-1].start))
            continue
         }
      }
      out = append(out, r)
   }
   return out
}

// imgSection is one PE section header as mapped.
type imgSection struct {
   va, vs, rs, rp uint32
}

// peSections reads SizeOfImage and the section table out of a PE file.
//
// A short or malformed header returns no sections and a zero SizeOfImage rather
// than panicking: callers pass a ReadFile result straight in, and a partially read
// file would otherwise die with a bare slice-bounds error naming the wrong culprit.
func peSections(fb []byte) (sizeImg uint32, secs []imgSection) {
   if len(fb) < 0x40 {
      return 0, nil
   }
   lf := int(le32(fb, 0x3C)) // e_lfanew
   // One bound covers every header field read below: NumberOfSections at lf+6,
   // SizeOfOptionalHeader at lf+20, and SizeOfImage at lf+24+56.
   if lf < 0 || lf+24+60 > len(fb) {
      return 0, nil
   }
   n := int(le16(fb, lf+6))
   opt := int(le16(fb, lf+20))
   sizeImg = le32(fb, lf+24+56)

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

// segSpans returns the RVA ranges a segment descriptor lists. Each entry is 0xC
// bytes from +0xF4: flags, rva, size. Entries that reach outside the image are
// dropped rather than clamped.
//
// -2 must not dedupe: its descriptors list overlapping spans, and deduping by RVA
// loses the later, larger ones.
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

// warbird.go end
