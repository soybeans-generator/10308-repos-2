// warbird.go begin
//go:build windows

// The Warbird descriptor format, the PE census that finds descriptors in a DLL on disk,
// the span and block carving, and -2, the op=1 segment decrypt.
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
// A descriptor has THREE addresses: its own (`va`), desc_va (+0x28, what op=3 is handed
// and what a call targets) and code rva (+0x34). The census stores all three.
//
// Segment descriptors list RVA ranges and all decrypt in one loaded image; heap-exec
// descriptors each need their own fresh LoadLibraryW, because the kernel honours only the
// FIRST such decrypt per image.
//
// PITFALLS. Do not compare the image hash between runs - LoadLibraryW bakes the load base
// into IAT slots and relocated fields, which is why the profile is keyed by the DLL's
// digest and the image is cross-checked by length. The descriptor size cap must stay at
// 0x200000; segment descriptors must be decrypted per descriptor, not per deduped RVA, or
// later/larger spans are lost; and the sacrificial page's protection must be restored
// before the WB call, or the kernel rejects it with 0xc000000d.
package main

import (
   "bytes"
   "cmp"
   "crypto/sha256"
   "encoding/binary"
   "fmt"
   "os"
   "slices"
   "unsafe"
)

// ------------------------------------------------------------- -2: op=1

// diCall issues op=1 (segment decrypt) for the descriptor at `sac` inside `base`.
// NTSTATUS comes back in RAX, so r1 is the whole answer.
func diCall(base, sac, rel, num uintptr) uint32 {
   var a [0x30]byte
   binary.LittleEndian.PutUint64(a[0x00:], 1)                // op = 1, segment decrypt
   binary.LittleEndian.PutUint64(a[0x08:], uint64(sac))      // descriptor address
   binary.LittleEndian.PutUint64(a[0x10:], uint64(base))     // image base
   binary.LittleEndian.PutUint64(a[0x18:], uint64(base))     // image base
   binary.LittleEndian.PutUint64(a[0x20:], uint64(base+rel)) // relocations
   binary.LittleEndian.PutUint64(a[0x28:], uint64(num))      // relocation count

   r1, _, _ := wbNtQuery.Call(0xB9, uintptr(unsafe.Pointer(&a[0])), 0x30, 0)
   return uint32(r1)
}

// diMakeDesc builds a synthetic 1-entry segment descriptor, reusing hdr's header shape so
// it matches what the kernel expects for this build:
//
//   [0x00..0x20)  sha256 over the body
//   [0x20]        total size (0x100)
//   [0x40..0xF0)  crypto params copied from a real descriptor
//   [0xF0]        entry count (1), +0xF4 flags, +0xF8 rva, +0xFC size
func diMakeDesc(hdr, params []byte, rva, size uint32) []byte {
   buf := make([]byte, 0x100)
   copy(buf[0x00:0x40], hdr)
   copy(buf[0x40:], params) // params is 0xB0 bytes -> lands at [0x40..0xF0)

   binary.LittleEndian.PutUint32(buf[0x20:], 0x100)
   binary.LittleEndian.PutUint32(buf[0xF0:], 1)
   binary.LittleEndian.PutUint32(buf[0xF4:], 0x30C)
   binary.LittleEndian.PutUint32(buf[0xF8:], rva)
   binary.LittleEndian.PutUint32(buf[0xFC:], size)

   sum := sha256.Sum256(buf[0x20:0x100])
   copy(buf[0x00:0x20], sum[:])
   return buf
}

// diReadMem copies n bytes out of the process we are running in. It is the one reader of
// mapped memory: -2 uses it for the image, -3's sweep for a table set.
func diReadMem(base uintptr, n int) []byte {
   out := make([]byte, n)
   copy(out, unsafe.Slice((*byte)(wbMemAt(base)), n))
   return out
}

func le16(b []byte, o int) uint16 {
   return binary.LittleEndian.Uint16(b[o:])
}

func le32(b []byte, o int) uint32 {
   return binary.LittleEndian.Uint32(b[o:])
}

func stageDecryptImg() (code int) {
   lg := newStepLog(imgLogPath)
   defer lg.Finish(&code)
   logf, fail := lg.Printf, lg.Failf

   if err := os.MkdirAll(outDir, 0o755); err != nil {
      return fail("cannot create %s: %v", outDir, err)
   }

   f, shaHex, err := pfDLL()
   if err != nil {
      return fail("cannot read %s: %v", dllPath, err)
   }

   sizeImg, secs := peSections(f)
   segs, heaps := splitDescs(f, secs)
   if len(segs) == 0 {
      return fail("no segment descriptors found")
   }

   // SLOT / RELOCS / NUM vary between builds, so they are read from a real segment
   // descriptor instead of being hardcoded. segs[0] is the sacrificial slot because a
   // genuine descriptor already carries its own self-address at +0x28, which the kernel
   // validates. The heap-exec pass overwrites it later, by which time the segment pass has
   // finished.
   slot := segs[0].va
   relocs := le32(f, int(segs[0].off)+0x2C)
   num := le32(f, int(segs[0].off)+0x30)

   logf("dll     %s", dllPath)
   logf("sha256  %s", shaHex)
   logf("image   0x%x (%d bytes)", sizeImg, sizeImg)
   logf("descriptors %d  segments %d  heap-exec %d", len(segs)+len(heaps), len(segs), len(heaps))
   logf("slot    0x%x  relocs 0x%x/%d", slot, relocs, num)
   logf("")

   // Segment pass: ONE loaded image, op=1 against every real segment descriptor.
   // Per-descriptor, not per-deduped-RVA: descriptors overlap, and deduping by RVA drops
   // the later/larger spans.
   base, err := wbLoad(dllPath)
   if err != nil {
      return fail("LoadLibraryW failed: %v", err)
   }

   ok := 0
   for _, s := range segs {
      rel := le32(f, int(s.off)+0x2C)
      n := le32(f, int(s.off)+0x30)
      if diCall(base, base+uintptr(s.va), uintptr(rel), uintptr(n)) == 0 {
         ok++
      }
   }
   logf("segment descriptors %d ok %d", len(segs), ok)

   img := diReadMem(base, int(sizeImg))
   if err := wbFree(base); err != nil {
      logf("warning: FreeLibrary after segment pass: %v", err)
   }
   logf("")

   // Heap-exec pass: ONE FRESH IMAGE PER BLOCK. Each iteration builds a synthetic
   // descriptor for (rva, size) from this block's own crypto params, writes it over the
   // sacrificial slot, restores the slot's protection (the kernel rejects a descriptor on
   // a writable page with 0xc000000d), decrypts, reads back and frees.
   //
   // A failed patch is reported as rc != 0 with no bytes: the call is skipped, and the
   // block belongs with the ones that failed rather than the ones that did not change.
   decryptBlock := func(h *imgDesc) (got []byte, rc uint32, err error) {
      lib, err := wbLoad(dllPath)
      if err != nil {
         return nil, 0, fmt.Errorf("LoadLibraryW failed at heap block 0x%x: %w", h.rva, err)
      }
      defer func() {
         if ferr := wbFree(lib); ferr != nil {
            logf("  warning: FreeLibrary at heap block 0x%x: %v", h.rva, ferr)
         }
      }()

      sac := lib + uintptr(slot)
      hdr := diReadMem(sac, 0x40)
      params := f[int(h.off)+0x40 : int(h.off)+0xF0]
      if !wbPatch(lib, slot, diMakeDesc(hdr, params, h.rva, h.ln)) {
         return nil, ^uint32(0), nil
      }

      rc = diCall(lib, sac, uintptr(relocs), uintptr(num))
      return diReadMem(lib+uintptr(h.rva), int(h.ln)), rc, nil
   }

   done, same, errCount := 0, 0, 0

   for i, h := range heaps {
      if h.rva == 0 || h.ln == 0 || uint64(h.rva)+uint64(h.ln) > uint64(sizeImg) {
         errCount++
         continue
      }
      before := img[h.rva : h.rva+h.ln]

      got, rc, err := decryptBlock(&h)
      if err != nil {
         return fail("%v", err)
      }

      switch {
      case rc != 0:
         errCount++
      case !bytes.Equal(got, before):
         copy(img[h.rva:], got)
         done++
      default:
         // was already plaintext (e.g. .data entries) - not an error
         same++
         if same <= 12 {
            logf("  unchanged 0x%06x+0x%x owner 0x%x", h.rva, h.ln, h.va)
         }
      }

      if (i+1)%200 == 0 {
         logf("  %d/%d  changed %d  same %d  err %d", i+1, len(heaps), done, same, errCount)
      }
   }

   logf("")
   logf("heap-exec %d  changed %d  unchanged %d  error %d", len(heaps), done, same, errCount)
   logf("")

   if err := os.WriteFile(imgPath, img, 0o644); err != nil {
      return fail("cannot write %s: %v", imgPath, err)
   }

   // -2 establishes the profile: it is the first step that knows the DLL's digest and
   // produces the artefact everything else is measured against.
   //
   // The census goes in here, not just SizeOfImage: scanDescs hashes several gigabytes, and
   // every trial child needs the spans and heap blocks it produces.
   //
   // pfLoad, not a fresh profile: re-running -2 against the same build must not discard a
   // map and a stage pairing that are still valid.
   cen := &profileCensus{}
   for _, s := range segs {
      for _, sp := range segSpans(f, &s, sizeImg) {
         cen.Spans = append(cen.Spans, [2]uint32{sp.start, sp.length})
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
   logf("written %s  (%d bytes)", imgPath, len(img))
   logf("sha256   %x", sha256.Sum256(img))
   return 0
}

// ------------------------------------------------------------- descriptors

// imgDesc is one digest-validated descriptor. va is its own address and identifies a
// candidate; descVA is +0x28 and is what a call inside the image targets; rva and ln are
// the code block, meaningful only for heap-exec descriptors; off and size are the
// descriptor's file position.
type imgDesc struct {
   va     uint32
   off    uint32
   size   uint32
   descVA uint32
   rva    uint32
   ln     uint32
}

// scanDescs returns every digest-validated descriptor in the file, in section order. A
// candidate is accepted when its size field is plausible and the SHA-256 over [0x20, size)
// matches the digest that precedes it; nothing else is checked, because the digest is the
// signature.
//
// THIS IS THE EXPENSIVE FUNCTION IN THE PROGRAM: it hashes every 4-byte offset whose size
// field lands in range. It runs once, in -2, and the result is cached.
//
// The 0x200000 cap must not be lowered: the two largest descriptors on the recorded build
// are 0x829c and 0x3cac bytes, and a 0x2000 cap silently skips them, which loses the gap
// blocks and makes -6 execute ciphertext.
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

         // top nibble of desc_va and of both heap-exec fields is a flag; the rest is an RVA
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

// splitDescs partitions a census into segment and heap-exec descriptors, in file order.
// -1 and -2 both need exactly this split.
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

// heap reports whether this is a heap-exec descriptor. 0xF0 is the only size the kernel
// treats that way, and the size field is covered by the digest, so the test cannot be
// spoofed by a corrupt byte.
func (d *imgDesc) heap() bool {
   return d.size == 0xF0
}

// imgRun is a half-open RVA range. It serves three jobs with one type: one heap-exec
// block, a merged run of them, and a segment span to patch.
type imgRun struct{ start, length uint32 }

// carveRuns returns [r, r+s) minus every interval, as the runs that remain.
//
// Both patching callers need it for the same reason: the kernel decrypts a heap-exec block
// itself on op=3, so copying already-decrypted bytes over one causes a double decrypt and
// the routine executes garbage.
func carveRuns(merged []imgRun, r, s uint32) []imgRun {
   var out []imgRun
   cur, end := r, r+s

   // Start at the last interval whose start is at or below r. BinarySearchFunc reports the
   // first entry not less than the target, so an exact hit is that entry and a miss leaves
   // pos one past the last candidate.
   pos, found := slices.BinarySearchFunc(merged, r, func(m imgRun, t uint32) int {
      return cmp.Compare(m.start, t)
   })
   if !found {
      pos = max(pos-1, 0)
   }

   for _, m := range merged[pos:] {
      hi := m.start + m.length
      if hi <= cur {
         continue
      }
      if m.start >= end {
         break
      }
      if m.start > cur {
         out = append(out, imgRun{cur, min(m.start, end) - cur})
      }
      if cur = max(cur, hi); cur >= end {
         break
      }
   }
   if cur < end {
      out = append(out, imgRun{cur, end - cur})
   }
   return out
}

// mergeRuns sorts and coalesces overlapping OR touching ranges, so carveRuns can
// binary-search them and the patcher can issue one VirtualProtect per merged run.
//
// Touching counts as overlapping because every run is written from the same source image:
// adjacent runs are equivalent to their union, and merging turns thousands of protection
// flips into a few dozen.
func mergeRuns(ivs []imgRun) []imgRun {
   slices.SortFunc(ivs, func(a, b imgRun) int { return cmp.Compare(a.start, b.start) })

   var out []imgRun
   for _, p := range ivs {
      if n := len(out); n > 0 {
         old := &out[n-1]
         if end := uint64(old.start) + uint64(old.length); uint64(p.start) <= end {
            old.length = uint32(max(end, uint64(p.start)+uint64(p.length)) - uint64(old.start))
            continue
         }
      }
      out = append(out, p)
   }
   return out
}

// segSpans returns the RVA ranges a segment descriptor lists. Each entry is 0xC bytes from
// +0xF4: flags, rva, size. Entries reaching outside the image are dropped.
//
// -2 must not dedupe: its descriptors list overlapping spans, and deduping by RVA loses the
// later, larger ones.
func segSpans(fb []byte, d *imgDesc, sizeImg uint32) []imgRun {
   if int(d.off)+int(d.size) > len(fb) {
      return nil
   }
   b := fb[d.off : d.off+d.size]

   var out []imgRun
   for o := 0xF4; o+0xC <= len(b); o += 0xC {
      rva, size := le32(b, o+4), le32(b, o+8)
      if rva >= 0x1000 && size >= 8 && uint64(rva)+uint64(size) <= uint64(sizeImg) {
         out = append(out, imgRun{rva, size})
      }
   }
   return out
}

// imgSection is one PE section header as mapped.
type imgSection struct {
   va, vs, rs, rp uint32
}

// peSections reads SizeOfImage and the section table out of a PE file. A short or
// malformed header returns no sections and a zero SizeOfImage rather than panicking:
// callers pass a ReadFile result straight in.
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

// warbird.go end
