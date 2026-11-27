// capture.go begin
//go:build windows

// prkf -4: dump the memory the stage routines read, so the emulator can run them elsewhere.
//
// WHY A MEMORY DUMP AT ALL: the decrypted image is not enough. The module is loaded at an
// address chosen at run time, and its data holds that address - in relocations the loader
// applied, and in pointers the module wrote into its own fields. Run against wbtool_img.bin
// at a made-up base, an instruction that loads one of those gets a value that points at
// nothing, which is the "no readable code at 0x7ffd51e4dc50" and "unmapped address
// 0x900000003c" a capture-less run produces. A capture fixes both.
//
// THE CAPTURE MUST FOLLOW A CALL, AND THIS STEP CANNOT BE TOLD WHICH ONE. PlayReady builds
// dispatch tables lazily. Measured on this build:
//
//   no call                 256 regions, stage-1 obf 5c322c45...  wrong
//   signing-key block       271 regions, stage-1 obf 5c322c45...  wrong
//   stage-1 block           270 regions, stage-1 obf f707e4e8...  correct
//
// So it calls EVERY candidate the image yields. The walk is the same image-only walk -7 does:
// find the size-check site, find the block that owns it, follow lea and call targets outward.
// The block that builds the tables is necessarily in that set, so the dump is necessarily
// taken from a process where it has run. Nothing here consults a sample.
//
// A FAULTING CANDIDATE IS SKIPPED THE WAY -1 SKIPS ONE. A fault is a Windows SEH exception in
// the DLL; it kills the child and leaves no end row. The last call row the parent received
// names the descriptor that faulted, so the parent drops it and re-runs the whole remaining
// list in a fresh child. The list shrinks by one per attempt, so it terminates, and the final
// child has called every survivor in one process.
//
// NO SAMPLE IS READ. The warm-up key is thirty-two zero bytes and the results are discarded:
// only the side effect is wanted.
//
// EVERY REGION IS READ WITH ReadProcessMemory, NOT BY DEREFERENCING IT. A direct read of a
// committed region can still fault, and a fault there takes the process down mid-dump.
//
// INPUTS   profilePath, imgPath
// OUTPUT   mem.bin, mem.json, capture.txt
package main

import (
   "bytes"
   "encoding/json"
   "fmt"
   "os"
   "slices"
   "strings"
   "unsafe"
)

const (
   memCommit    = 0x1000
   protNoAccess = 0x01
   protGuard    = 0x100
   scanStart    = 0x1000
   scanLimit    = 0x7FFF_FFFE_0000
   regionCap    = 0x0400_0000 // 64 MiB
   totalCap     = 0x3000_0000 // 768 MiB
   readChunk    = 0x0001_0000 // 64 KiB

   // warmLn is the stage-1 call shape. Every candidate is called with it; the ones that
   // expect another shape reject, which is harmless.
   warmLn = 0x2C
)

func cmdCapture() (code int) {
   lg := newStepLog(captureLogPath)
   defer lg.Finish(&code)
   say, fail := lg.Printf, lg.Failf

   pi, err := pfPrep()
   if err != nil {
      return fail("%v", err)
   }

   cands, err := warmCandidates(pi.img, pi.heaps)
   if err != nil {
      return fail("%v", err)
   }
   say("dll     %s", pi.sha)
   say("image   %s  %d bytes", imgPath, len(pi.img))
   say("cands   %d descriptors from the image alone", len(cands))
   say("")

   if len(cands) == 0 {
      return fail("no candidates - the lea/call idiom differs on this build")
   }

   // A fault costs the child and everything behind it, so the descriptor that faulted is
   // dropped and the whole remaining list is re-run: the child that finally dumps has called
   // every survivor in one process.
   faulty := map[uint32]bool{}
   attempts := 0

   for {
      var list []uint32
      for _, d := range cands {
         if !faulty[d] {
            list = append(list, d)
         }
      }
      if len(list) == 0 {
         return fail("every candidate faulted - nothing could be warmed")
      }
      attempts++

      p := runCollect(&childSpec{Mode: "warm", Descs: list}, 0,
         func(s string) { say("  %s", strings.TrimPrefix(s, "  ")) })
      if p.err != nil {
         return fail("spawn: %v", p.err)
      }
      rows, err := readRows(p.stdout)
      if err != nil {
         return fail("%v", err)
      }

      var dumped bool
      var lastCall uint32
      for _, r := range rows {
         switch r.Kind {
         case "call":
            lastCall = r.Desc
         case "meta":
            say("  %s", r.Msg)
         case "err", "loadfail":
            return fail("%s", r.Msg)
         case "fault":
            say("  fault: %s", r.Msg)
         }
         if r.Kind == "meta" && strings.HasPrefix(r.Msg, "DUMP ") {
            dumped = true
         }
      }

      if dumped && ended(rows) {
         break
      }
      if lastCall == 0 {
         return fail("child stopped without calling anything (rows above)")
      }
      faulty[lastCall] = true
      say("  0x%06x faulted - dropped, re-running the remaining %d",
         lastCall, len(list)-1)
      say("")
   }

   say("")
   say("attempts %d, faulting descriptors %d", attempts, len(faulty))
   if fi, err := os.Stat(memPath); err == nil {
      say("written %s  (%d bytes, %.1f MiB)",
         memPath, fi.Size(), float64(fi.Size())/(1<<20))
   }
   if fi, err := os.Stat(memMapPath); err == nil {
      say("written %s  (%d bytes)", memMapPath, fi.Size())
   }
   return 0
}

// dumpRegions writes mem.bin and mem.json from the process it is called in.
func dumpRegions(base uintptr, sha string) (int, uint64, error) {
   proc := ^uintptr(0) // GetCurrentProcess

   var (
      regs    []memRegion
      buf     []byte
      total   uint64
      blank   uint64
      addr    = uint64(scanStart)
      dropped int
      partial int
   )
   for addr < scanLimit {
      var m memBasic
      r, _, _ := wbVirtualQuery.Call(uintptr(addr), uintptr(unsafe.Pointer(&m)),
         unsafe.Sizeof(m))
      if r == 0 || m.RegionSize == 0 {
         break
      }
      next := m.BaseAddress + m.RegionSize

      readable := m.State == memCommit &&
         m.Protect != 0 &&
         m.Protect&protNoAccess == 0 &&
         m.Protect&protGuard == 0
      fits := m.RegionSize <= regionCap && total+m.RegionSize <= totalCap

      switch {
      case readable && fits:
         dst := make([]byte, m.RegionSize)
         b := readRegion(proc, m.BaseAddress, m.RegionSize, dst)
         if b == m.RegionSize {
            dropped++
            break
         }
         if b != 0 {
            partial++
         }
         off := uint64(len(buf))
         buf = append(buf, dst...)
         regs = append(regs, memRegion{
            Addr: m.BaseAddress, Size: m.RegionSize, Off: off, Blank: b,
         })
         total += m.RegionSize
         blank += b

      case readable:
         dropped++
      }
      addr = next
   }

   if len(regs) == 0 {
      return 0, 0, fmt.Errorf("no captured regions")
   }
   if err := os.WriteFile(memPath, buf, 0o644); err != nil {
      return 0, 0, fmt.Errorf("write %s: %v", memPath, err)
   }
   mm := memMapFile{
      ImageBase: uint64(base),
      DLLSHA256: sha,
      Regions:   regs,
      Total:     total,
   }
   blob, err := json.MarshalIndent(&mm, "", " ")
   if err != nil {
      return 0, 0, err
   }
   if err := os.WriteFile(memMapPath, append(blob, '\n'), 0o644); err != nil {
      return 0, 0, fmt.Errorf("write %s: %v", memMapPath, err)
   }
   return len(regs), total, nil
}

// readRegion copies one region into dst, chunk by chunk, and returns how many bytes could not
// be read. A failed chunk stays zero: the offset of every byte after it is unchanged, which
// is what keeps the address map valid.
func readRegion(proc uintptr, addr, size uint64, dst []byte) uint64 {
   var bad uint64
   for off := uint64(0); off < size; off += readChunk {
      n := size - off
      if n > readChunk {
         n = readChunk
      }
      var got uintptr
      r, _, _ := wbReadProc.Call(
         proc,
         uintptr(addr+off),
         uintptr(unsafe.Pointer(&dst[off])),
         uintptr(n),
         uintptr(unsafe.Pointer(&got)),
      )
      switch {
      case r == 0:
         bad += n
      case uint64(got) < n:
         bad += n - uint64(got)
      }
   }
   return bad
}

// warmCandidates is the image-only walk: the size-check site, the block that owns it, and
// every descriptor a lea or call target reaches from there. Nothing here consults a sample.
func warmCandidates(img []byte, heaps []imgDesc) ([]uint32, error) {
   const (
      tol     = 0x20 // a lea/call target this close to a descriptor is that descriptor
      winSz   = 0x400
      maxHops = 10
      maxBlk  = 20000
   )

   blockOf := func(rva int) (*imgDesc, bool) {
      for i := range heaps {
         h := &heaps[i]
         if h.ln != 0 && int(h.rva) <= rva && rva < int(h.rva+h.ln) {
            return h, true
         }
      }
      return nil, false
   }
   matchDesc := func(t int) (uint32, bool) {
      best, bestDist := uint32(0), tol+1
      for _, h := range heaps {
         for _, v := range [2]uint32{h.va, h.descVA} {
            d := int(v) - t
            if d < 0 {
               d = -d
            }
            if d < bestDist {
               best, bestDist = h.va, d
            }
         }
      }
      return best, bestDist <= tol
   }

   if bytes.Count(img, dpPattern) != 1 {
      return nil, fmt.Errorf("expected exactly one 'cmp dword ptr [rcx+0x14], 0x41' in the image")
   }
   site := bytes.Index(img, dpPattern)
   owner, ok := blockOf(site)
   if !ok {
      return nil, fmt.Errorf("no heap-exec block owns the size check")
   }

   cand := map[uint32]bool{}
   visited := map[[2]int]bool{}
   frontier := [][2]int{{int(owner.rva), int(owner.ln)}}
   depth := 0

   for len(frontier) > 0 && depth < maxHops && len(visited) < maxBlk {
      depth++
      var nxt [][2]int
      for _, b := range frontier {
         if visited[b] {
            continue
         }
         visited[b] = true

         hi := min(b[0]+b[1], len(img)-8)
         for o := max(0x1000, b[0]); o < hi; o++ {
            var t int
            switch {
            case (img[o] == 0x48 || img[o] == 0x4C) && img[o+1] == 0x8D:
               switch img[o+2] {
               case 5, 0xD, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D:
                  t = o + 7 + int(int32(le32(img, o+3)))
               default:
                  continue
               }
            case img[o] == 0xE8 || img[o] == 0xE9:
               t = o + 5 + int(int32(le32(img, o+1)))
            default:
               continue
            }
            if m, ok := matchDesc(t); ok {
               cand[m] = true
               continue
            }
            if h, ok := blockOf(t); ok {
               nxt = append(nxt, [2]int{int(h.rva), int(h.ln)})
            } else if t >= 0x1000 && t < len(img)-0x40 {
               nxt = append(nxt, [2]int{t, min(winSz, len(img)-t)})
            }
         }
      }
      frontier = nxt
   }

   out := make([]uint32, 0, len(cand))
   for d := range cand {
      out = append(out, d)
   }
   slices.Sort(out)
   return out, nil
}

// warmWorker is -4's child: load, patch the spans, call every descriptor it was given, then
// patch the plaintext blocks and dump. A call row is emitted before each call so that a
// process death names the descriptor that caused it.
func warmWorker(spec childSpec) {
   defer emit(childRow{Kind: "end"})

   pi, err := pfPrep()
   if err != nil {
      emit(childRow{Kind: "loadfail", Msg: err.Error()})
      return
   }
   base, err := loadWarbird()
   if err != nil {
      emit(childRow{Kind: "loadfail", Msg: err.Error()})
      return
   }
   pi.apply(base)

   // Before any call: a fault must be reported rather than taking the child down silently.
   if !wbVEH(base) {
      emit(childRow{Kind: "loadfail", Msg: "AddVectoredExceptionHandler returned NULL"})
      return
   }

   op3 := op3Call(base)
   for _, d := range spec.Descs {
      emit(childRow{Kind: "call", Desc: d})
      var sb [0x40]byte
      var kb [0x40]byte
      var ob [0x40]byte
      rc := op3(d, warmLn, keyLen, sb[:], kb[:keyLen], ob[:keyLen], nil)
      emit(childRow{Kind: "meta", Msg: fmt.Sprintf("RET %06x rc=%x st=%x",
         d, rc, sb[:4])})
   }

   // Plaintext code over the encrypted blocks, now that the calls are done. Doing it earlier
   // would put plaintext under a kernel call that decrypts again.
   for i := range pi.heaps {
      h := &pi.heaps[i]
      if h.ln == 0 || uint64(h.rva)+uint64(h.ln) > uint64(len(pi.img)) {
         continue
      }
      if !wbPatch(base, h.rva, pi.img[h.rva:h.rva+h.ln]) {
         emit(childRow{Kind: "err", Msg: fmt.Sprintf("patch block 0x%06x: VirtualProtect failed", h.va)})
         return
      }
   }

   n, total, err := dumpRegions(base, pi.sha)
   if err != nil {
      emit(childRow{Kind: "err", Msg: err.Error()})
      return
   }
   emit(childRow{Kind: "meta", Msg: fmt.Sprintf("DUMP %d %d", n, total)})
}

type memBasic struct {
   BaseAddress       uint64
   AllocationBase    uint64
   AllocationProtect uint32
   _                 uint32
   RegionSize        uint64
   State             uint32
   Protect           uint32
   Type              uint32
   _                 uint32
}

// capture.go end
