// trials.go begin
//go:build windows

// The child bodies that drive the DLL, and the parsers on the parent side of each. The
// plumbing they share - the spec, the spawn, the grammar - is child.go.
//
//   dmWorker    -3's sweep: one image patch, then every family
//   dpWorker    -6's trial, both phases
//   probeBatch  the parent side of -1's probe child, which lives in signing.go
//
// A worker returns no verdict. Every one reports by row and closes with k=end; a fault, a
// kill or a death inside native code is the absence of that row.
package main

import (
   "bytes"
   "encoding/binary"
   "encoding/hex"
   "fmt"
   "os"
   "path/filepath"
   "time"
   "unsafe"
)

// ------------------------------------------------------- the -3 sweep child

// Static, never-moved scratch handed to native code.
var (
   dmKB  [0x48]byte
   dmARG [0x40]byte
   dmCB  [0x80]byte
)

// dmCall runs the consumer on one blob with the given 0x41-byte key and returns
// (ntstatus, status dword, 0x20-byte output). It is NOT op3Call: this routine takes a blob,
// so the argument block is a different shape.
//
//   +0x00  op = 3
//   +0x08  descriptor address
//   +0x10  -> status dword
//   +0x18  u32 0
//   +0x1C  -> key       (unaligned: a uintptr, like the output pointer below)
//   +0x24  u32 key size = 0x41
//   +0x28  -> blob
//   +0x30  -> output
//
// The status dword and the output are locals, so the returned slices are owned by the caller.
func dmCall(base uintptr, desc uint32, prv, blob []byte) (uint32, []byte, []byte) {
   var st [4]byte
   var out [0x20]byte

   copy(dmKB[:], prv)
   copy(dmCB[:], blob)
   a := dmARG[:0x38]
   binary.LittleEndian.PutUint64(a[0x00:], 3)
   binary.LittleEndian.PutUint64(a[0x08:], uint64(base)+uint64(desc))
   binary.LittleEndian.PutUint64(a[0x10:], uint64(uintptr(unsafe.Pointer(&st[0]))))
   binary.LittleEndian.PutUint32(a[0x18:], 0)
   binary.LittleEndian.PutUint64(a[0x1C:], uint64(uintptr(unsafe.Pointer(&dmKB[0]))))
   binary.LittleEndian.PutUint32(a[0x24:], 0x41)
   binary.LittleEndian.PutUint64(a[0x28:], uint64(uintptr(unsafe.Pointer(&dmCB[0]))))
   binary.LittleEndian.PutUint64(a[0x30:], uint64(uintptr(unsafe.Pointer(&out[0]))))
   r, _, _ := wbNtQuery.Call(0xB9, uintptr(unsafe.Pointer(&a[0])), 0x38, 0)
   return uint32(r), st[:], out[:]
}

// dmLoadFail emits the loadfail row the parent parses; the caller then unwinds.
func dmLoadFail(f string, a ...any) {
   emit(childRow{Kind: "loadfail", Msg: fmt.Sprintf(f, a...)})
}

// dmPrv is a synthetic 0x41-byte key component: the first 0x40 bytes a fixed non-repeating
// pattern, byte 0x40 the family selector. Only -3 uses it, because forcing the table
// collapses whatever this key derives.
func dmPrv(family int) []byte {
   var p [0x41]byte
   for i := 0; i < 0x40; i++ {
      p[i] = byte(i*37 + 0x5A)
   }
   p[0x40] = byte(family)
   return p[:]
}

// dmWorker is the sweep child: one image patch, then every family.
func dmWorker(desc uint32, fams []int, sets []uint32) {
   defer emit(childRow{Kind: "end"})

   // Every blob is read before the image is touched, so a missing licence fails in
   // milliseconds instead of after the span patch.
   blobs := make(map[int][]byte, 15)
   for nn := 1; nn <= 15; nn++ {
      b, err := os.ReadFile(filepath.Join(oracleDir, fmt.Sprintf("lic_%02x.blob", nn)))
      if err != nil {
         dmLoadFail("licence %02x: %v", nn, err)
         return
      }
      blobs[nn] = b
   }

   pi, err := pfPrep()
   if err != nil {
      dmLoadFail("%v", err)
      return
   }
   base, err := loadWarbird()
   if err != nil {
      dmLoadFail("%v", err)
      return
   }

   patched, skipped := pi.apply(base)
   emit(childRow{Kind: "meta", Msg: fmt.Sprintf("PATCHED %d skipped %d", patched, skipped)})

   // A false return means the child runs unprotected: a fault then kills it with no fault
   // row, and the driver reads that as missing rows.
   if !wbVEH(base) {
      dmLoadFail("AddVectoredExceptionHandler returned NULL")
      return
   }

   // A failed patch does not merely skip work: the forced nibble is not forced, so every
   // row for that set is garbage. It is fatal.
   force := func(rva uint32, v byte) error {
      if !wbPatch(base, rva, bytes.Repeat([]byte{v}, dmCLEN)) {
         return fmt.Errorf("patch set 0x%x: VirtualProtect failed", rva)
      }
      return nil
   }

   for _, f := range fams {
      prv := dmPrv(f)

      // ---- phase 1: which set does this family read? ----------------------
      // Forcing 16 different nibbles through a table the routine reads gives 16 different
      // outputs; a set it never reads gives the same output 16 times. Each force
      // overwrites all of dmCLEN, so only the last one needs undoing.
      liveIdx, nLive := -1, 0
      for i, srva := range sets {
         orig := diReadMem(base+uintptr(srva), dmCLEN)
         seen := map[string]bool{}
         ok := true
         for mm := 0; mm < 16; mm++ {
            if err := force(srva, byte(mm)); err != nil {
               dmLoadFail("%v", err)
               return
            }
            rc, sd, res := dmCall(base, desc, prv, blobs[1])
            if rc != 0 || !statusOK(sd) {
               ok = false
               break
            }
            seen[hex.EncodeToString(res)] = true
         }
         if !wbPatch(base, srva, orig) {
            dmLoadFail("restore set 0x%x: VirtualProtect failed", srva)
            return
         }
         d := len(seen)
         if !ok {
            d = 0
         }
         emit(childRow{Kind: "meta", Msg: fmt.Sprintf("PROBE %d %d %d", f, i, d)})
         if d == 16 {
            nLive++
            if liveIdx < 0 {
               liveIdx = i
            }
         }
      }
      if nLive != 1 {
         emit(childRow{Kind: "nolive", Fam: f, Idx: nLive})
         continue
      }

      srva := sets[liveIdx]
      emit(childRow{Kind: "live", Fam: f, Idx: liveIdx, Desc: srva})

      // ---- phase 2: the full permutation ---------------------------------
      // Forced nibble outer, licence inner: one protection flip per forced value instead
      // of one per call.
      orig := diReadMem(base+uintptr(srva), dmCLEN)
      for mm := 0; mm < 16; mm++ {
         if err := force(srva, byte(mm)); err != nil {
            dmLoadFail("%v", err)
            return
         }
         for nn := 1; nn <= 15; nn++ {
            _, sd, res := dmCall(base, desc, prv, blobs[nn])
            emit(childRow{Kind: "out", Fam: f, Idx: nn, Half: mm,
               St:  []string{hex.EncodeToString(sd)},
               Buf: []string{hex.EncodeToString(res)}})
         }
         if !wbPatch(base, srva, orig) {
            dmLoadFail("restore set 0x%x: VirtualProtect failed", srva)
            return
         }
      }
   }
}

// ------------------------------------------------------- the -6 trial child

// dpHalf returns one 0x20-byte half of the key component. Byte 0x40 is never handed to a
// stage.
func dpHalf(prv []byte, h int) []byte {
   if h == 1 {
      return prv[0x20:0x40]
   }
   return prv[0:0x20]
}

// dpPrv reads the sample's 0x41-byte key component. The stage routines reject material that
// is not real, which is why a synthetic key made the search unfindable.
func dpPrv() ([]byte, error) {
   prv, err := os.ReadFile(encPrvPath)
   if err != nil {
      return nil, fmt.Errorf("missing %s - run prkf -4 first", encPrvPath)
   }
   if len(prv) != 0x41 {
      return nil, fmt.Errorf("%s is %d bytes, expected 0x41 (65)", encPrvPath, len(prv))
   }
   return prv, nil
}

// dpTrial runs one op=3 trial. k1 goes in the key buffer, k2 in the output buffer; ln and
// size2 are the only things that differ between the phases.
func dpTrial(op3 op3Func, desc, ln uint32, k1, k2 []byte, size2 *uint32) (kb, out []byte, rc uint32, st []byte) {
   var sb [0x40]byte
   var b1 [0x40]byte
   var b2 [0x40]byte
   copy(b1[:], k1)
   copy(b2[:], k2) // nil k2 leaves this zero-filled

   rc = op3(desc, ln, 0x20, sb[:], b1[:], b2[:], size2)
   return b1[:0x20], b2[:0x20], rc, sb[:4]
}

// dpWorker is the trial body for both phases: phase 1 is 0x2C bytes with no second size, key
// half in the key buffer and a zeroed output; phase 2 is 0x30 with a 0x20 there, OBF in the
// key buffer and the key half in the output buffer. Phase 1 is phase 2 with one empty OBF.
//
// The index is flattened as (di*len(obfs)+oi)*2+h because that is one resume point, but each
// row names its own descriptor, OBF and half: the parent never re-derives them.
func dpWorker(mode string, start int, obfs []string, descs []uint32) {
   defer func() {
      if r := recover(); r != nil {
         emit(childRow{Kind: "err", Msg: fmt.Sprint(r)})
      }
      emit(childRow{Kind: "end"})
   }()

   op3, prv, err := dpPrepChild()
   if err != nil {
      emit(childRow{Kind: "err", Msg: err.Error()})
      return
   }

   sz := uint32(0x20)
   ln, szp := uint32(0x2C), (*uint32)(nil)
   if mode == "p2" {
      ln, szp = 0x30, &sz
   }

   n := len(obfs)
   for idx := start; idx < len(descs)*n*2; idx++ {
      di, oi, h := idx/(n*2), idx%(n*2)/2, idx%2
      k1, k2 := dpHalf(prv, h), []byte(nil)
      if obfs[oi] != "" {
         var derr error
         if k1, derr = hex.DecodeString(obfs[oi]); derr != nil || len(k1) != 0x20 {
            emit(childRow{Kind: "err", Msg: fmt.Sprintf("bad obf %q", obfs[oi])})
            return
         }
         k2 = dpHalf(prv, h)
      }
      kb, out, rc, st := dpTrial(op3, descs[di], ln, k1, k2, szp)
      if rc != 0 || !statusOK(st) {
         emit(childRow{Kind: "reject", Desc: descs[di], Idx: oi, Half: h,
            St: []string{hex.EncodeToString(st)}})
         continue
      }
      emit(childRow{Kind: "ok", Desc: descs[di], Idx: oi, Half: h,
         Buf: []string{hex.EncodeToString(kb), hex.EncodeToString(out)}})
   }
}

// ------------------------------------------------------------ -1's parent side

// probeBatch runs one probe child for a list of descriptors and returns the verdict row each
// produced, keyed by descriptor VA. A descriptor with no row faulted or was never reached.
//
// No deadline, and stderr is streamed into w: a hung chunk never exits, so its last trace
// line is the only evidence of where it stopped.
func probeBatch(descs []imgDesc, w func(string)) map[uint32]childRow {
   out := map[uint32]childRow{}
   if len(descs) == 0 {
      return out
   }

   vas := make([]uint32, len(descs))
   for i, d := range descs {
      vas[i] = d.descVA
   }

   p := runCollect(&childSpec{Mode: "probe", Descs: vas}, 0, w)
   if p.err != nil {
      w("  spawn: " + p.err.Error())
      return out
   }
   rows, err := readRows(p.stdout)
   if err != nil {
      w("  " + err.Error())
      return out
   }
   if !ended(rows) {
      w("  child did not finish - no end row")
   }
   for _, r := range rows {
      switch r.Kind {
      case "accept", "reject", "none":
         out[r.Desc] = r
      case "fault", "err":
         w("  " + r.Msg)
      }
   }
   return out
}

// dpPrepChild loads what a trial needs and patches the image: the one place a child pays its
// fixed cost.
func dpPrepChild() (op3 op3Func, prv []byte, err error) {
   pi, err := pfPrep()
   if err != nil {
      return nil, nil, err
   }
   if prv, err = dpPrv(); err != nil {
      return nil, nil, err
   }
   base, err := loadWarbird()
   if err != nil {
      return nil, nil, err
   }
   pi.apply(base)

   if !wbVEH(base) {
      return nil, nil, fmt.Errorf("AddVectoredExceptionHandler returned NULL")
   }
   return op3Call(base), prv, nil
}

// ------------------------------------------------------------ -3's parent side

// dmFam is one family's rows from a sweep child. nLive is 1 when exactly one set answered 16
// distinct outputs; liveRVA is that set.
type dmFam struct {
   nLive   int
   liveRVA uint32
   outs    map[int]map[int]string // licence -> forced nibble -> hex
}

// dmResult is one sweep child, parsed. ended is whether it printed its end row: a run without
// one is incomplete, and an incomplete run is not a verdict.
type dmResult struct {
   fams  map[int]*dmFam
   meta  []string
   fault string
   err   error
   ended bool
}

// dmSweep spawns one sweep child for the given families and parses its rows.
func dmSweep(descRVA uint32, fams []int, sets []uint32) *dmResult {
   p := runCollect(&childSpec{
      Mode:  "sweep",
      Descs: []uint32{descRVA},
      Fams:  fams,
      Sets:  sets,
   }, 30*time.Minute, nil)

   r := &dmResult{fams: map[int]*dmFam{}}
   if p.err != nil {
      r.err = p.err
      return r
   }
   rows, err := readRows(p.stdout)
   if err != nil {
      r.err = err
      return r
   }
   r.ended = ended(rows)

   fam := func(i int) *dmFam {
      if r.fams[i] == nil {
         r.fams[i] = &dmFam{outs: map[int]map[int]string{}}
      }
      return r.fams[i]
   }

   for _, x := range rows {
      switch x.Kind {
      case "meta":
         // PATCHED and PROBE are the per-set evidence behind the live-set verdict.
         r.meta = append(r.meta, x.Msg)

      case "loadfail", "err":
         r.err = fmt.Errorf("%s", x.Msg)
      case "fault":
         r.fault = x.Msg

      case "live":
         fm := fam(x.Fam)
         fm.liveRVA, fm.nLive = x.Desc, 1

      case "nolive":
         fm := fam(x.Fam)
         fm.nLive, fm.liveRVA = x.Idx, 0

      case "out":
         // A value that is not 0x20 hex bytes would silently match nothing, and dmPerm
         // would report it as an incomplete sweep rather than a bad row.
         if len(x.Buf) != 1 || !isHex32(x.Buf[0]) {
            r.err = fmt.Errorf("out row: buffer %q is not 0x20 hex bytes", x.Buf)
            return r
         }
         fm := fam(x.Fam)
         if fm.outs[x.Idx] == nil {
            fm.outs[x.Idx] = map[int]string{}
         }
         fm.outs[x.Idx][x.Half] = x.Buf[0]
      }
   }
   return r
}

// dmSweepAll is dmSweep plus the fault fallback: one child covers all families, so a fault
// costs every family at once. Re-running one family at a time salvages the rest, and costs
// nothing when the batch succeeds. A child with no end row takes the same path: it was killed
// on the deadline or died in native code, so the families it did not finish are missing.
func dmSweepAll(descRVA uint32, fams []int, sets []uint32, logf func(string, ...any)) *dmResult {
   r := dmSweep(descRVA, fams, sets)
   if r.err != nil || len(fams) <= 1 {
      return r
   }
   if r.fault == "" && r.ended {
      return r
   }

   logf("  batch child stopped early - retrying one family at a time")
   for _, f := range fams {
      if fm, ok := r.fams[f]; ok && (fm.nLive != 1 || len(fm.outs) == 15) {
         continue
      }
      one := dmSweep(descRVA, []int{f}, sets)
      if one.err != nil {
         r.err = one.err
         return r
      }
      if fm, ok := one.fams[f]; ok {
         r.fams[f] = fm
      }
   }
   r.fault = ""
   return r
}

// trials.go end
