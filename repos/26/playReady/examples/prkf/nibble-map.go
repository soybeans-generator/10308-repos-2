// nibblemap.go begin
//go:build windows

// prkf -6: magic-independent stage 3 of the nibble chain
// =============================================================================
//
// wbtool_img.bin + extracted.enc.prv + the oracle licences -> oracle_map.json
//
// DISCRIMINATOR (no magic needed)
//   For set S, forced mapped nibble m, licence NN:
//       O(S,m,NN) = X(C2 - d'(m)*C1) XOR magic
//   with d'(m) the scalar whose every nibble is MAP[m]. Decryption reaches the
//   sentinel iff MAP[m] == NN. Hence
//     - S not live : 16 outputs identical per licence (equal to control), and
//                    different between licences.
//     - S live     : 16 outputs vary, and exactly one is the SAME 32 bytes for
//                    every licence (the sentinel X, which is licence-independent).
//   So |intersection over licences| == 1  <=>  S is live, and the shared value
//   is SENT XOR magic. magic is then recovered rather than assumed.
//
//   If NO set yields a shared value, the sentinel is never produced: the blob /
//   ECC encoding is wrong, not the table.
//
// PHASES
//   1  all discovered sets x licences 01/02/03  -> live set + magic
//   2  live set x licences 01..0f               -> full permutation
//
// INPUTS   imgPath, encPrvPath, oracleDir/lic_NN.blob
// OUTPUT   mapPath  {"cluster": rva, "magic": hex, "map": {...}}
//          mapLogPath
//
// USAGE
//   prkf -6
//
//   No flags of its own. Every path above is a manifest entry in main.go.
//
//   The sweep runs in a child of this same binary, using positional arguments
//   rather than flags:
//     prkf -6 sweep <setRVA> <descRVA> <lics>
//   That is the internal worker; the driver spawns it, nothing else should.
//
// The descriptor format, the PE census, the block carving, the span lookup, the
// page patch and the fault handler are all shared with -5 and -7 and live in
// warbird.go.
// =============================================================================

package main

import (
   "bytes"
   "context"
   "crypto/sha256"
   "encoding/binary"
   "encoding/hex"
   "encoding/json"
   "fmt"
   "os"
   "os/exec"
   "path/filepath"
   "strconv"
   "strings"
   "syscall"
   "time"
   "unsafe"
)

const (
   dmCBLK, dmCN, dmCLEN = 16, 64, 0x400
   dmKBL                = 0x48
)

var (
   dmPAT  = []byte{0x83, 0x79, 0x14, 0x41} // cmp [rcx+0x14],0x41
   dmSENT = append([]byte("HELLO MICROSOFT!"), make([]byte, 16)...)
   dmW10  = dmHx("a77bece491a87ebcd8a2c62856b165b33ad2572cf88bdae3ddc79be816be3185")
   dmW11  = dmHx("c3cd57691eff156c95d946d534121dfb81738adb5b4bb4223faad89cbb459bec")
)

// ================================ worker =====================================

var (
   // Static, never-moved scratch handed to native code.
   dmST  [0x40]byte
   dmOUT [0x100]byte
   dmKB  [dmKBL]byte
   dmARG [0x40]byte
   dmCB  []byte
)

var dmDesc uint32

// ================================ driver =====================================

var dmLogLines []string

// dmCensus splits a scan into segment and heap-exec descriptors and collects
// the segment spans, in descriptor order. The spans are not deduplicated: -6
// patches every range a descriptor lists, and overlapping ranges are harmless
// here because each is written from the same image.
func dmCensus(fb []byte, secs []imgSection, sizeImg uint32) ([]imgDesc, []imgDesc, []imgSpan) {
   var segs, heaps []imgDesc
   var spans []imgSpan
   for _, d := range scanDescs(fb, secs) {
      if d.heap() {
         heaps = append(heaps, d)
         continue
      }
      segs = append(segs, d)
      spans = append(spans, segSpans(fb, d, sizeImg)...)
   }
   return segs, heaps, spans
}

func dmDie(f string, a ...any) {
   dmLogf("FATAL: "+f, a...)
   if err := os.WriteFile(mapLogPath, []byte(strings.Join(dmLogLines, "\n")+"\n"), 0o644); err != nil {
      fmt.Fprintf(os.Stderr, "prkf -6: %s: %v\n", mapLogPath, err)
   }
   os.Exit(1)
}

// dmFindSets is a literal port of re.finditer(rb"[\x00-\x0f]{1024,}") plus the
// sliding bijection test. Runs of bytes <= 0x0f of length >= dmCLEN are visited
// left to right; within each run o advances by dmCLEN on a hit and by 1 on a
// miss. Offsets come out ascending, so no sort is needed. One byte comparison
// per iteration, no rune decoding.
func dmFindSets(img []byte) []uint32 {
   var out []uint32
   for i := 0; i < len(img); {
      if img[i] > 0x0f {
         i++
         continue
      }
      lo := i
      for i < len(img) && img[i] <= 0x0f {
         i++
      }
      for o := lo; o+dmCLEN <= i; {
         j := 0
         for ; j < dmCN; j++ {
            if !dmUniq(img[o+j*dmCBLK : o+(j+1)*dmCBLK]) {
               break
            }
         }
         if j == dmCN {
            out = append(out, uint32(o))
            o += dmCLEN
         } else {
            o++
         }
      }
   }
   return out
}

// dmHx parses a hex constant. A malformed constant is a programming error, and
// silently returning nil would make the Windows 10/11 comparisons below false
// for the wrong reason, so it panics at init instead.
func dmHx(s string) []byte {
   b, err := hex.DecodeString(s)
   if err != nil {
      panic("dmHx: bad hex constant: " + s)
   }
   return b
}

func dmLoadFail(f string, a ...any) {
   fmt.Printf("LOADFAIL "+f+"\n", a...)
   os.Exit(4)
}

func dmLogf(f string, a ...any) {
   s := fmt.Sprintf(f, a...)
   dmLogLines = append(dmLogLines, s)
   fmt.Println(s)
}

func dmUniq(b []byte) bool {
   var seen [256]bool
   for _, c := range b {
      if seen[c] {
         return false
      }
      seen[c] = true
   }
   return true
}

func dmWorker(setArg, descArg, licsArg string) {
   if setArg == "" || descArg == "" || licsArg == "" {
      fmt.Fprintln(os.Stderr, "usage: prkf -6 sweep <setRVA> <descRVA> <lics>")
      os.Exit(2)
   }
   arg := func(s string, base int) int {
      v, err := strconv.ParseInt(s, base, 64)
      if err != nil {
         dmLoadFail("bad arg %q", s)
      }
      return int(v)
   }
   must := func(p string) []byte {
      b, err := os.ReadFile(p)
      if err != nil {
         dmLoadFail("%v", err)
      }
      return b
   }
   srva, desc := arg(setArg, 0), arg(descArg, 0)
   var lics []int
   for _, x := range strings.Split(licsArg, ",") {
      lics = append(lics, arg(x, 16))
   }

   fb, img, prv := must(dllPath), must(imgPath), must(encPrvPath)
   copy(dmKB[:], prv) // create_string_buffer(PRV, 0x48): zero-padded

   sizeImg, secs := peSections(fb)
   _, heaps, spans := dmCensus(fb, secs, sizeImg)

   wp, err := syscall.UTF16PtrFromString(dllPath)
   if err != nil {
      dmLoadFail("%v", err)
   }
   bp, _, lerr := wbLoadLibraryW.Call(uintptr(unsafe.Pointer(wp)))
   base := uintptr(bp)
   if base == 0 {
      dmLoadFail("LoadLibraryW: %v", lerr)
   }

   // --- prep: patch segment plaintext, but never over a heap-exec block.
   // The kernel decrypts those itself on op=3; pre-filling them causes a
   // double decrypt and the routine executes garbage.
   var ivs []imgInterval
   for _, h := range heaps {
      if h.ln != 0 {
         ivs = append(ivs, imgInterval{h.rva, h.rva + h.ln})
      }
   }
   merged := mergeIntervals(ivs)

   patched, skipped := 0, 0
   for _, sp := range spans {
      r, n := sp.rva, sp.size
      if uint64(r)+uint64(n) > uint64(len(img)) {
         continue
      }
      c := rawAt(fb, secs, r, n) // the DLL's own plaintext at this span
      if c == nil || bytes.Equal(img[r:r+n], c) {
         continue
      }
      for _, run := range carveRuns(merged, r, n) {
         if wbPatch(base, run.start, img[run.start:run.start+run.length]) {
            patched++
         } else {
            skipped++
         }
      }
   }
   fmt.Printf("PATCHED %d skipped %d\n", patched, skipped)
   fmt.Printf("VARIANT prv[0x40]=0x%02x %%3=%d\n", dmKB[0x40], dmKB[0x40]%3)

   // A false return means the child runs unprotected: a fault then kills it with
   // no FAULT line, the sweep comes back with no OUT rows, and the driver reads
   // that as "incomplete" - the one diagnosis this step must not confuse with a
   // result.
   if !wbVEH(base, func(s string) { fmt.Println(s) }) {
      dmLoadFail("AddVectoredExceptionHandler returned NULL")
   }

   orig := make([]byte, dmCLEN)
   copy(orig, unsafe.Slice((*byte)(wbMemAt(base+uintptr(srva))), dmCLEN))

   decrypt := func(blob []byte) (uint32, []byte, []byte) {
      clear(dmST[:])
      clear(dmOUT[:])
      copy(dmKB[:], prv)
      dmCB = append(dmCB[:0], blob...)
      a := dmARG[:0x38]
      binary.LittleEndian.PutUint64(a[0x00:], 3)
      binary.LittleEndian.PutUint64(a[0x08:], uint64(base)+uint64(desc))
      binary.LittleEndian.PutUint64(a[0x10:], uint64(uintptr(unsafe.Pointer(&dmST[0]))))
      binary.LittleEndian.PutUint32(a[0x18:], 0)
      binary.LittleEndian.PutUint64(a[0x1C:], uint64(uintptr(unsafe.Pointer(&dmKB[0]))))
      binary.LittleEndian.PutUint32(a[0x24:], 0x41)
      binary.LittleEndian.PutUint64(a[0x28:], uint64(uintptr(unsafe.Pointer(&dmCB[0]))))
      binary.LittleEndian.PutUint64(a[0x30:], uint64(uintptr(unsafe.Pointer(&dmOUT[0]))))
      r, _, _ := wbNtQuery.Call(0xB9, uintptr(unsafe.Pointer(&a[0])), 0x38, 0)
      return uint32(r), append([]byte(nil), dmST[:4]...), append([]byte(nil), dmOUT[:0x20]...)
   }

   // A failed patch here does not merely skip work: the forced nibble is not
   // forced, so every OUT row for that licence is garbage and the permutation
   // comes out wrong. It is fatal for the same reason a missing licence is.
   force := func(v byte) {
      if !wbPatch(base, uint32(srva), bytes.Repeat([]byte{v}, dmCLEN)) {
         dmLoadFail("patch set 0x%x: VirtualProtect failed", srva)
      }
   }

   for _, nn := range lics {
      // A missing licence is fatal, not skipped: skipping one makes every set
      // report "incomplete" and sends the driver into its blob/ECC-encoding
      // analysis, which is the wrong diagnosis for a missing file.
      blob, err := os.ReadFile(filepath.Join(oracleDir, fmt.Sprintf("lic_%02x.blob", nn)))
      if err != nil {
         dmLoadFail("licence %02x: %v", nn, err)
      }
      rc, sd, res := decrypt(blob)
      fmt.Printf("CTRL %02x rc=0x%08x st=%x %x\n", nn, rc, sd, res)
      for mm := 0; mm < 16; mm++ {
         force(byte(mm))
         rc, sd, res := decrypt(blob)
         if !wbPatch(base, uint32(srva), orig) {
            dmLoadFail("restore set 0x%x: VirtualProtect failed", srva)
         }
         fmt.Printf("OUT %02x %02x rc=0x%08x st=%x %x\n", nn, mm, rc, sd, res)
      }
   }
   os.Exit(0)
}

// --- stage entry point ------------------------------------------------------

func stageDeriveMap(args []string) int {
   // Internal worker mode. Positional, so the command line surface stays at
   // exactly -1 through -7.
   if len(args) > 0 && args[0] == "sweep" {
      if len(args) != 4 {
         fmt.Fprintln(os.Stderr, "usage: prkf -6 sweep <setRVA> <descRVA> <lics>")
         return 2
      }
      dmWorker(args[1], args[2], args[3])
      return 0
   }
   if len(args) > 0 {
      fmt.Fprintf(os.Stderr, "prkf -6: unexpected argument %q\n", args[0])
      return 2
   }

   if err := os.MkdirAll(outDir, 0o755); err != nil {
      dmDie("cannot create %s: %v", outDir, err)
   }

   for _, f := range []string{imgPath, encPrvPath} {
      if _, err := os.Stat(f); err != nil {
         dmDie("missing %s", f)
      }
   }
   if _, err := os.Stat(oracleDir); err != nil {
      dmDie("missing %s - run prkf -4 first", oracleDir)
   }
   read := func(p string) []byte {
      b, err := os.ReadFile(p)
      if err != nil {
         dmDie("%v", err)
      }
      return b
   }
   fb, img := read(dllPath), read(imgPath)

   sizeImg, secs := peSections(fb)
   segs, heaps, spans := dmCensus(fb, secs, sizeImg)

   sum := sha256.Sum256(fb)
   dmLogf("dll      %s", dllPath)
   dmLogf("sha256   %x", sum)
   dmLogf("size     %d   SizeOfImage 0x%x", len(fb), sizeImg)
   dmLogf("image    %s  %d bytes", imgPath, len(img))
   dmLogf("segments %d  heap-exec %d  spans %d", len(segs), len(heaps), len(spans))
   dmLogf("")

   SETS := dmFindSets(img)
   dmLogf("bijection sets: %d", len(SETS))
   for i, rva := range SETS {
      dmLogf("  set%d  0x%06x  %x", i, rva, img[rva:min(rva+16, uint32(len(img)))])
   }
   dmLogf("")
   if len(SETS) == 0 {
      dmDie("no permutation sets found - is wbtool_img.bin decrypted?")
   }

   h, sites, ok := dmFindConsumer(img, heaps)
   dmLogf("size-check sites: %#x", sites)
   if !ok {
      dmDie("consumer not unique (%d sites)", len(sites))
   }
   dmLogf("consumer descriptor 0x%06x  code 0x%06x+0x%x", h.va, h.rva, h.ln)
   dmLogf("")
   dmDesc = h.va

   // ---- phase 1: live set + magic, using three licences
   P1 := []int{1, 2, 3}
   dmLogf("phase 1: %d sets x licences %v", len(SETS), P1)
   dmLogf("%-6s%-10s%-10s%-8s%s", "set", "rva", "distinct", "shared", "verdict")

   var (
      liveIdx  int
      liveRVA  uint32
      haveLive bool
      magic    string

      // The set the routine demonstrably reads even when no forced nibble lands
      // on the sentinel: whichever varies the most. Its table is printed below
      // when nothing is live, because that is the evidence separating a wrong
      // blob order from a wrong table.
      bestTab  dmSweep
      bestRVA  uint32
      bestMinD int

      metaOnce bool
   )

   // PATCHED and VARIANT do not depend on the set, so the first sweep that
   // returns them is enough. Printed before any verdict, not after: the failure
   // path below tells the reader to check the variant, and used to be the one
   // path where the line carrying it was never written.
   showMeta := func(r dmSweep) {
      if metaOnce || len(r.meta) == 0 {
         return
      }
      metaOnce = true
      for _, m := range r.meta {
         dmLogf("  %s", m)
      }
      dmLogf("")
   }

   for i, rva := range SETS {
      r := dmRun(rva, P1)
      showMeta(r)
      if r.loadfail != "" {
         dmDie("%s", r.loadfail)
      }
      if r.fault != "" {
         dmLogf("set%-3d0x%06x  %s", i, rva, r.fault)
         continue
      }
      if len(r.outs) < len(P1) {
         dmLogf("set%-3d0x%06x  incomplete (rc %d)", i, rva, r.rc)
         continue
      }

      distinct, cnt, minD := map[int]int{}, map[string]int{}, 1<<30
      for _, nn := range P1 {
         seen := map[string]bool{}
         for _, v := range r.outs[nn] {
            seen[v] = true
         }
         distinct[nn] = len(seen)
         minD = min(minD, distinct[nn])
         for v := range seen {
            cnt[v]++
         }
      }
      var shared []string
      for v, c := range cnt {
         if c == len(P1) {
            shared = append(shared, v)
         }
      }
      verdict := "not live"
      if len(shared) == 1 && minD > 1 {
         verdict = "LIVE"
      }
      dmLogf("set%-3d0x%06x  %2d %2d %2d  %-8d%s",
         i, rva, distinct[1], distinct[2], distinct[3], len(shared), verdict)
      if verdict == "LIVE" {
         if haveLive {
            dmDie("two live sets: 0x%06x and 0x%06x", liveRVA, rva)
         }
         haveLive, liveIdx, liveRVA, magic = true, i, rva, shared[0]
      }
      if minD > bestMinD {
         bestTab, bestRVA, bestMinD = r, rva, minD
      }
   }
   dmLogf("")

   if !haveLive {
      dmLogf("no set produced a shared plaintext across licences.")
      dmLogf("")

      if bestMinD > 1 {
         dmLogf("The set at 0x%06x IS read by the routine: %d distinct outputs per",
            bestRVA, bestMinD)
         dmLogf("licence, so the patch reaches it and the descriptor is the consumer.")
         dmLogf("What is missing is the sentinel. Same forced nibble m, one row per")
         dmLogf("m, 'lics' counting how many of the %d licences produced that output:", len(P1))
         dmLogf("")
         dmLogf("  %-4s%-6s%s", "m", "lics", "output")
         for mm := 0; mm < 16; mm++ {
            v, ok := bestTab.outs[P1[0]][mm]
            if !ok {
               continue
            }
            n := 0
            for _, nn := range P1 {
               if bestTab.outs[nn][mm] == v {
                  n++
               }
            }
            dmLogf("  %02x  %d/%d   %s", mm, n, len(P1), v)
         }
         dmLogf("")
         dmLogf("A %d/%d row is the sentinel, and the permutation falls out of it. No",
            len(P1), len(P1))
         dmLogf("%d/%d row means the derived scalar is not MAP[m] repeated for any m,",
            len(P1), len(P1))
         dmLogf("so either this build reads the blob's points in the other order (swap")
         dmLogf("C1||C2 in lic_NN.blob) or the table the routine uses is not among the")
         dmLogf("%d sets above.", len(SETS))
      } else {
         dmLogf("No set changed the output at all, so the routine reads none of the %d", len(SETS))
         dmLogf("sets: the consumer is wrong on this build, or the table is not a plain")
         dmLogf("nibble array in wbtool_img.bin.")
      }
      dmLogf("")
      dmLogf("The VARIANT line above names the routine family prv[0x40]%%3 selects.")
      dmDie("no live set")
   }

   mh, herr := hex.DecodeString(magic)
   if herr != nil {
      dmDie("shared value from the sweep is not hex: %q", magic)
   }
   MAGIC := make([]byte, min(len(mh), len(dmSENT)))
   for i := range MAGIC {
      MAGIC[i] = mh[i] ^ dmSENT[i]
   }

   dmLogf("live set   set%d 0x%06x", liveIdx, liveRVA)
   dmLogf("magic      %x", MAGIC)
   switch {
   case bytes.Equal(MAGIC, dmW10):
      dmLogf("           == the Windows 10 sequence")
   case bytes.Equal(MAGIC, dmW11):
      dmLogf("           == the Windows 11 sequence")
   default:
      dmLogf("           == NEITHER published sequence: this build uses a third one,")
      dmLogf("              which is why a hardcoded W10 constant would never match.")
   }
   dmLogf("")

   // ---- phase 2: full permutation on the live set
   dmLogf("phase 2: full permutation on the live set")
   r := dmRun(liveRVA, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
   if r.loadfail != "" {
      dmDie("%s", r.loadfail)
   }
   if r.fault != "" {
      dmDie("%s", r.fault)
   }
   if len(r.outs) < 15 {
      dmDie("incomplete sweep (rc %d)", r.rc)
   }
   MAP := map[int]int{}
   for nn := 1; nn < 16; nn++ {
      var hits []int
      for mm, v := range r.outs[nn] {
         if v == magic {
            hits = append(hits, mm)
         }
      }
      if len(hits) != 1 {
         dmDie("nibble 0x%x: %d hits, expected 1", nn, len(hits))
      }
      mm := hits[0]
      if p, used := MAP[mm]; used {
         dmDie("nibble 0x%x: mapped 0x%x already used by real 0x%x", nn, mm, p)
      }
      MAP[mm] = nn
      dmLogf("  real 0x%x <- mapped 0x%x", nn, mm)
   }

   var left []int
   for m := 0; m < 16; m++ {
      if _, ok := MAP[m]; !ok {
         left = append(left, m)
      }
   }
   if len(left) != 1 {
      dmDie("expected one leftover, got %#x", left)
   }
   MAP[left[0]] = 0
   dmLogf("  leftover mapped 0x%x -> real 0x0", left[0])
   dmLogf("")

   // 16 distinct values drawn from 0..15 is a bijection: a duplicate is the
   // only way to fail.
   var seen [16]bool
   for _, v := range MAP {
      if seen[v] {
         dmDie("not a bijection: 0x%x twice", v)
      }
      seen[v] = true
   }

   dmLogf("[MAP]  mapped -> real")
   for m := 0; m < 16; m++ {
      dmLogf("  %x -> %x", m, MAP[m])
   }

   jm := map[string]int{}
   for k, v := range MAP {
      jm[strconv.Itoa(k)] = v
   }
   blob, err := json.MarshalIndent(map[string]any{
      "cluster": liveRVA, "magic": hex.EncodeToString(MAGIC), "map": jm,
   }, "", "  ")
   if err != nil {
      dmDie("%v", err)
   }
   if err := os.WriteFile(mapPath, blob, 0o644); err != nil {
      dmDie("%v", err)
   }
   dmLogf("")
   dmLogf("written %s", mapPath)
   // The sweep log is the only record of how the permutation was derived, so a
   // failure to write it is reported instead of discarded.
   if err := os.WriteFile(mapLogPath, []byte(strings.Join(dmLogLines, "\n")+"\n"), 0o644); err != nil {
      fmt.Fprintf(os.Stderr, "prkf -6: %s: %v\n", mapLogPath, err)
      return 1
   }
   return 0
}

// dmFindConsumer returns the heap-exec descriptor owning the unique size-check
// site, so the driver does not have to look it up a second time.
func dmFindConsumer(img []byte, heaps []imgDesc) (imgDesc, []int, bool) {
   var sites []int
   for i := 0; ; {
      j := bytes.Index(img[i:], dmPAT)
      if j < 0 {
         break
      }
      sites = append(sites, i+j)
      i += j + 1
   }
   if len(sites) != 1 {
      return imgDesc{}, sites, false
   }
   var owner imgDesc
   found := false
   for _, h := range heaps {
      if h.ln != 0 && h.rva <= uint32(sites[0]) && uint32(sites[0]) < h.rva+h.ln {
         owner, found = h, true
      }
   }
   return owner, sites, found
}

type dmSweep struct {
   outs     map[int]map[int]string
   meta     []string
   fault    string
   loadfail string
   rc       int
}

func dmRun(setrva uint32, lics []int) dmSweep {
   // A failure here leaves exe empty, so the spawn fails, every sweep comes back
   // with no OUT rows and the run dies blaming an incomplete sweep.
   exe, err := os.Executable()
   if err != nil {
      return dmSweep{loadfail: "LOADFAIL os.Executable: " + err.Error()}
   }
   ps := make([]string, len(lics))
   for i, x := range lics {
      ps[i] = fmt.Sprintf("%02x", x)
   }
   ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
   defer cancel()
   // Positional worker arguments, not flags: the child re-derives every path
   // from the same manifest the parent used.
   cmd := exec.CommandContext(ctx, exe, "-6", "sweep",
      fmt.Sprintf("0x%x", setrva),
      fmt.Sprintf("0x%x", dmDesc),
      strings.Join(ps, ","))
   var so bytes.Buffer
   cmd.Stdout = &so
   err = cmd.Run()

   r := dmSweep{outs: map[int]map[int]string{}}
   if ee, ok := err.(*exec.ExitError); ok {
      r.rc = ee.ExitCode()
   }
   for _, ln := range strings.Split(so.String(), "\n") {
      f := strings.Fields(ln)
      if len(f) < 2 {
         continue
      }
      switch f[0] {
      case "PATCHED", "VARIANT":
         r.meta = append(r.meta, ln)
      case "LOADFAIL":
         r.loadfail = ln
      case "FAULT":
         r.fault = ln
      case "OUT":
         nn, err := strconv.ParseInt(f[1], 16, 64)
         if err != nil {
            r.loadfail = "LOADFAIL bad OUT index: " + ln
            return r
         }
         mm, err := strconv.ParseInt(f[2], 16, 64)
         if err != nil {
            r.loadfail = "LOADFAIL bad OUT nibble: " + ln
            return r
         }
         if r.outs[int(nn)] == nil {
            r.outs[int(nn)] = map[int]string{}
         }
         r.outs[int(nn)][int(mm)] = f[len(f)-1]
      }
   }
   return r
}

// nibblemap.go end
