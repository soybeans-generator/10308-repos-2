//go:build windows

// 3-derive-map.go -- magic-independent stage 3
// =============================================================================
//
// Stage 3: wbtool_img.bin + extracted.enc.prv + the oracle licences
//          -> oracle_map.json
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
// INPUTS   testdata/wbtool_img.bin, testdata/extracted.enc.prv,
//          testdata/oracle/lic_NN.blob
// OUTPUT   testdata/oracle_map.json  {"cluster": rva, "magic": hex, "map": {...}}
//          testdata/derive_map.txt
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
   "sort"
   "strconv"
   "strings"
   "syscall"
   "time"
   "unsafe"
)

const (
   DATA                     = "testdata"
   CBLK, CN, CLEN, RWX, KBL = 16, 64, 0x400, 0x40, 0x48
   DLL                      = `C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll`
)

var (
   IMG, PRVF         = data("wbtool_img.bin"), data("extracted.enc.prv")
   ORACLE, OUTF, LOG = data("oracle"), data("oracle_map.json"), data("derive_map.txt")
   PAT               = []byte{0x83, 0x79, 0x14, 0x41} // cmp [rcx+0x14],0x41
   SENT              = append([]byte("HELLO MICROSOFT!"), make([]byte, 16)...)
   W10               = hx("a77bece491a87ebcd8a2c62856b165b33ad2572cf88bdae3ddc79be816be3185")
   W11               = hx("c3cd57691eff156c95d946d534121dfb81738adb5b4bb4223faad89cbb459bec")
)

// ================================ worker =====================================

var (
   LoadLibraryW   = syscall.NewLazyDLL("kernel32.dll").NewProc("LoadLibraryW")
   VirtualProtect = syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualProtect")
   GetMapped      = syscall.NewLazyDLL("kernel32.dll").NewProc("K32GetMappedFileNameW")
   AddVEH         = syscall.NewLazyDLL("kernel32.dll").NewProc("AddVectoredExceptionHandler")
   NtQuery        = syscall.NewLazyDLL("ntdll.dll").NewProc("NtQuerySystemInformation")
   RtlMove        = syscall.NewLazyDLL("ntdll.dll").NewProc("RtlMoveMemory")

   // Static, never-moved scratch handed to native code.
   gST  [0x40]byte
   gOUT [0x100]byte
   gKB  [KBL]byte
   gARG [0x40]byte
   gNM  [512]uint16
   gCB  []byte
   veh  uintptr
)

var gDesc uint32

// ================================ driver =====================================

var logLines []string

func census(fb []byte, secs []sec, sizeImg uint32) ([]blk, []blk, [][2]uint32) {
   var segs, heaps []blk
   for _, s := range secs {
      b := cut(fb, s.rp, s.rs)
      for off := 0; off+0x40 < len(b); off += 4 {
         sz := u32(b, off+0x20)
         if sz < 0x40 || sz > 0x200000 || off+int(sz) > len(b) {
            continue
         }
         if h := sha256.Sum256(b[off+0x20 : off+int(sz)]); !bytes.Equal(h[:], b[off:off+32]) {
            continue
         }
         d := blk{s.va + uint32(off), s.rp + uint32(off),
            u32(b, off+0x34) & 0x0FFFFFFF, u32(b, off+0x38) & 0x0FFFFFFF}
         if sz == 0xF0 {
            heaps = append(heaps, d)
         } else {
            d.size = sz
            segs = append(segs, d)
         }
      }
   }
   var spans [][2]uint32
   for _, g := range segs { // per descriptor, NOT deduped by RVA
      b := cut(fb, g.fo, g.size)
      for k := 0; 0xF4+k*0xC <= len(b)-0xC; k++ {
         rva, sz := u32(b, 0xF4+k*0xC+4), u32(b, 0xF4+k*0xC+8)
         if rva >= 0x1000 && sz >= 8 && rva+sz <= sizeImg {
            spans = append(spans, [2]uint32{rva, sz})
         }
      }
   }
   return segs, heaps, spans
}

// cut is Python's forgiving slice b[off:off+n], truncated at len(b).
func cut(b []byte, off, n uint32) []byte {
   if int(off) >= len(b) {
      return b[:0]
   }
   return b[off:min(int(off)+int(n), len(b))]
}

func data(n string) string { return filepath.Join(DATA, n) }

func die(f string, a ...any) {
   logf("FATAL: "+f, a...)
   os.WriteFile(LOG, []byte(strings.Join(logLines, "\n")+"\n"), 0o644)
   os.Exit(1)
}

// findSets is a literal port of re.finditer(rb"[\x00-\x0f]{1024,}") plus the
// sliding bijection test. Runs of bytes <= 0x0f of length >= CLEN are visited
// left to right; within each run o advances by CLEN on a hit and by 1 on a
// miss. Offsets come out ascending, so no sort is needed. One byte comparison
// per iteration, no rune decoding.
func findSets(img []byte) []uint32 {
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
      for o := lo; o+CLEN <= i; {
         j := 0
         for ; j < CN; j++ {
            if !uniq(img[o+j*CBLK : o+(j+1)*CBLK]) {
               break
            }
         }
         if j == CN {
            out = append(out, uint32(o))
            o += CLEN
         } else {
            o++
         }
      }
   }
   return out
}

func hx(s string) []byte { b, _ := hex.DecodeString(s); return b }

func loadfail(f string, a ...any) {
   fmt.Printf("LOADFAIL "+f+"\n", a...)
   os.Exit(4)
}

func logf(f string, a ...any) {
   s := fmt.Sprintf(f, a...)
   logLines = append(logLines, s)
   fmt.Println(s)
}

func main() {
   os.MkdirAll(DATA, 0o755)
   if len(os.Args) > 1 && os.Args[1] == "--sweep" {
      worker()
      return
   }

   for _, f := range []string{IMG, PRVF} {
      if _, err := os.Stat(f); err != nil {
         die("missing %s", f)
      }
   }
   if _, err := os.Stat(ORACLE); err != nil {
      die("missing %s - run make-oracle first", ORACLE)
   }
   read := func(p string) []byte {
      b, err := os.ReadFile(p)
      if err != nil {
         die("%v", err)
      }
      return b
   }
   fb, img := read(DLL), read(IMG)

   sizeImg, secs := pe(fb)
   segs, heaps, spans := census(fb, secs, sizeImg)

   sum := sha256.Sum256(fb)
   logf("dll      %s", DLL)
   logf("sha256   %x", sum)
   logf("size     %d   SizeOfImage 0x%x", len(fb), sizeImg)
   logf("image    %s  %d bytes", IMG, len(img))
   logf("segments %d  heap-exec %d  spans %d", len(segs), len(heaps), len(spans))
   logf("")

   SETS := findSets(img)
   logf("bijection sets: %d", len(SETS))
   for i, rva := range SETS {
      logf("  set%d  0x%06x  %x", i, rva, img[rva:min(rva+16, uint32(len(img)))])
   }
   logf("")
   if len(SETS) == 0 {
      die("no permutation sets found - is wbtool_img.bin decrypted?")
   }

   h, sites, ok := findConsumer(img, heaps)
   logf("size-check sites: %#x", sites)
   if !ok {
      die("consumer not unique (%d sites)", len(sites))
   }
   logf("consumer descriptor 0x%06x  code 0x%06x+0x%x", h.desc, h.rva, h.size)
   logf("")
   gDesc = h.desc

   // ---- phase 1: live set + magic, using three licences
   P1 := []int{1, 2, 3}
   logf("phase 1: %d sets x licences %v", len(SETS), P1)
   logf("%-6s%-10s%-10s%-8s%s", "set", "rva", "distinct", "shared", "verdict")

   var (
      liveIdx   int
      liveRVA   uint32
      haveLive  bool
      magic     string
      liveTable sweep
   )
   for i, rva := range SETS {
      r := run(rva, P1)
      if r.loadfail != "" {
         die("%s", r.loadfail)
      }
      if r.fault != "" {
         logf("set%-3d0x%06x  %s", i, rva, r.fault)
         continue
      }
      if len(r.outs) < len(P1) {
         logf("set%-3d0x%06x  incomplete (rc %d)", i, rva, r.rc)
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
      logf("set%-3d0x%06x  %2d %2d %2d  %-8d%s",
         i, rva, distinct[1], distinct[2], distinct[3], len(shared), verdict)
      if verdict == "LIVE" {
         if haveLive {
            die("two live sets: 0x%06x and 0x%06x", liveRVA, rva)
         }
         haveLive, liveIdx, liveRVA, magic, liveTable = true, i, rva, shared[0], r
      }
   }
   logf("")

   if !haveLive {
      logf("no set produced a shared plaintext across licences.")
      logf("")
      logf("That rules out both wrong-magic and wrong-live-set: if the sentinel were")
      logf("ever produced, the shared value would appear. So the sentinel is never")
      logf("reached at all, which points at the blob/ECC encoding rather than at the")
      logf("tables. Check, in order:")
      logf("  1. lic_NN.blob point order - C1||C2 vs C2||C1. The oracle writes")
      logf("     C1=(rG) then C2=(M+rQ); a build that reads C2 first never lands on M.")
      logf("  2. Whether the consumer really is the 0x41 licence consumer on this")
      logf("     build. Compare the 'distinct' column: all-1 means the patch has no")
      logf("     effect on the output, so that descriptor is not reading the table.")
      logf("  3. Whether prv[0x40]%%3 selects a routine family whose table is not among")
      logf("     the discovered sets - the VARIANT line above records the value.")
      die("no live set")
   }

   mh := hx(magic)
   MAGIC := make([]byte, min(len(mh), len(SENT)))
   for i := range MAGIC {
      MAGIC[i] = mh[i] ^ SENT[i]
   }

   logf("live set   set%d 0x%06x", liveIdx, liveRVA)
   logf("magic      %x", MAGIC)
   switch {
   case bytes.Equal(MAGIC, W10):
      logf("           == the Windows 10 sequence")
   case bytes.Equal(MAGIC, W11):
      logf("           == the Windows 11 sequence")
   default:
      logf("           == NEITHER published sequence: this build uses a third one,")
      logf("              which is why a hardcoded W10 constant would never match.")
   }
   logf("")
   for _, m := range liveTable.meta {
      logf("  %s", m)
   }

   // ---- phase 2: full permutation on the live set
   logf("")
   logf("phase 2: full permutation on the live set")
   r := run(liveRVA, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
   if r.fault != "" {
      die("%s", r.fault)
   }
   if len(r.outs) < 15 {
      die("incomplete sweep (rc %d)", r.rc)
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
         die("nibble 0x%x: %d hits, expected 1", nn, len(hits))
      }
      mm := hits[0]
      if p, used := MAP[mm]; used {
         die("nibble 0x%x: mapped 0x%x already used by real 0x%x", nn, mm, p)
      }
      MAP[mm] = nn
      logf("  real 0x%x <- mapped 0x%x", nn, mm)
   }

   var left []int
   for m := 0; m < 16; m++ {
      if _, ok := MAP[m]; !ok {
         left = append(left, m)
      }
   }
   if len(left) != 1 {
      die("expected one leftover, got %#x", left)
   }
   MAP[left[0]] = 0
   logf("  leftover mapped 0x%x -> real 0x0", left[0])
   logf("")

   // 16 distinct values drawn from 0..15 is a bijection: a duplicate is the
   // only way to fail.
   var seen [16]bool
   for _, v := range MAP {
      if seen[v] {
         die("not a bijection: 0x%x twice", v)
      }
      seen[v] = true
   }

   logf("[MAP]  mapped -> real")
   for m := 0; m < 16; m++ {
      logf("  %x -> %x", m, MAP[m])
   }

   jm := map[string]int{}
   for k, v := range MAP {
      jm[strconv.Itoa(k)] = v
   }
   blob, err := json.MarshalIndent(map[string]any{
      "cluster": liveRVA, "magic": hex.EncodeToString(MAGIC), "map": jm,
   }, "", "  ")
   if err != nil {
      die("%v", err)
   }
   if err := os.WriteFile(OUTF, blob, 0o644); err != nil {
      die("%v", err)
   }
   logf("")
   logf("written %s", OUTF)
   os.WriteFile(LOG, []byte(strings.Join(logLines, "\n")+"\n"), 0o644)
}

// ------------------------------------------------------------------ PE census

func pe(fb []byte) (uint32, []sec) {
   lf := int(u32(fb, 0x3C))
   n, osz := int(u16(fb, lf+6)), int(u16(fb, lf+20))
   secs := make([]sec, n)
   for i, p := 0, lf+24+osz; i < n; i, p = i+1, p+40 {
      secs[i] = sec{u32(fb, p+12), u32(fb, p+16), u32(fb, p+20)}
   }
   return u32(fb, lf+24+56), secs
}
func u16(b []byte, o int) uint16 { return binary.LittleEndian.Uint16(b[o:]) }
func u32(b []byte, o int) uint32 { return binary.LittleEndian.Uint32(b[o:]) }

func uniq(b []byte) bool {
   var seen [256]bool
   for _, c := range b {
      if seen[c] {
         return false
      }
      seen[c] = true
   }
   return true
}

func worker() {
   if len(os.Args) < 5 {
      fmt.Println("usage: <exe> --sweep SETRVA DESC LICS")
      os.Exit(2)
   }
   arg := func(s string, base int) int {
      v, err := strconv.ParseInt(s, base, 64)
      if err != nil {
         loadfail("bad arg %q", s)
      }
      return int(v)
   }
   must := func(p string) []byte {
      b, err := os.ReadFile(p)
      if err != nil {
         loadfail("%v", err)
      }
      return b
   }
   srva, desc := arg(os.Args[2], 0), arg(os.Args[3], 0)
   var lics []int
   for _, x := range strings.Split(os.Args[4], ",") {
      lics = append(lics, arg(x, 16))
   }

   fb, img, prv := must(DLL), must(IMG), must(PRVF)
   copy(gKB[:], prv) // create_string_buffer(PRV, 0x48): zero-padded

   sizeImg, secs := pe(fb)
   _, heaps, spans := census(fb, secs, sizeImg)

   wp, err := syscall.UTF16PtrFromString(DLL)
   if err != nil {
      loadfail("%v", err)
   }
   bp, _, lerr := LoadLibraryW.Call(uintptr(unsafe.Pointer(wp)))
   base := uintptr(bp)
   if base == 0 {
      loadfail("LoadLibraryW: %v", lerr)
   }

   // base stays a uintptr; memory traffic goes through RtlMoveMemory, so no
   // uintptr is ever converted back into a Go pointer.
   wr := func(rva uint32, buf []byte) bool {
      span := uintptr((len(buf) + 0xFFF) &^ 0xFFF)
      addr := base + uintptr(rva)
      var old, dummy uint32
      if r, _, _ := VirtualProtect.Call(addr, span, RWX, uintptr(unsafe.Pointer(&old))); r == 0 {
         return false
      }
      RtlMove.Call(addr, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
      VirtualProtect.Call(addr, span, uintptr(old), uintptr(unsafe.Pointer(&dummy)))
      return true
   }

   // --- prep: patch segment plaintext, but never over a heap-exec block.
   // The kernel decrypts those itself on op=3; pre-filling them causes a
   // double decrypt and the routine executes garbage.
   sort.Slice(heaps, func(i, j int) bool { return heaps[i].rva < heaps[j].rva })
   var merged [][2]uint32
   for _, h := range heaps {
      if h.size == 0 {
         continue
      }
      lo, hi := h.rva, h.rva+h.size
      if n := len(merged); n > 0 && lo <= merged[n-1][1] {
         merged[n-1][1] = max(merged[n-1][1], hi)
      } else {
         merged = append(merged, [2]uint32{lo, hi})
      }
   }

   // carve subtracts heap-exec blocks from [r,r+s); returns remaining runs as
   // (start,len). Every append is guarded, so no empty run can be produced.
   carve := func(r, s uint32) [][2]uint32 {
      e, cur := r+s, r
      var out [][2]uint32
      i := sort.Search(len(merged), func(j int) bool { return merged[j][0] > r })
      for _, b := range merged[max(i-1, 0):] {
         if b[1] <= cur {
            continue
         }
         if b[0] >= e {
            break
         }
         if b[0] > cur {
            out = append(out, [2]uint32{cur, min(b[0], e) - cur})
            cur = b[0]
         }
         cur = max(cur, b[1])
         if cur >= e {
            break
         }
      }
      if cur < e {
         out = append(out, [2]uint32{cur, e - cur})
      }
      return out
   }

   patched, skipped := 0, 0
   for _, sp := range spans {
      r, n := sp[0], sp[1]
      if uint64(r)+uint64(n) > uint64(len(img)) {
         continue
      }
      var c []byte // the DLL's own plaintext at this span, if readable
      for _, s := range secs {
         if s.va <= r && r < s.va+s.rs {
            if o := s.rp + r - s.va; int(o)+int(n) <= len(fb) {
               c = fb[o : o+n]
            }
         }
      }
      if c == nil || bytes.Equal(img[r:r+n], c) {
         continue
      }
      for _, run := range carve(r, n) {
         if wr(run[0], img[run[0]:run[0]+run[1]]) {
            patched++
         } else {
            skipped++
         }
      }
   }
   fmt.Printf("PATCHED %d skipped %d\n", patched, skipped)
   fmt.Printf("VARIANT prv[0x40]=0x%02x %%3=%d\n", gKB[0x40], gKB[0x40]%3)

   veh = syscall.NewCallback(func(ep *exceptionPointers) uintptr {
      mod := "-"
      if r, _, _ := GetMapped.Call(^uintptr(0), ep.Record.Address,
         uintptr(unsafe.Pointer(&gNM[0])), 512); r != 0 {
         if s := syscall.UTF16ToString(gNM[:]); s != "" {
            mod = s[strings.LastIndex(s, `\`)+1:]
         }
      }
      fmt.Printf("FAULT 0x%08x addr=0x%016x off=%+#x module=%s\n",
         ep.Record.Code, ep.Record.Address,
         int64(ep.Record.Address)-int64(base), mod)
      os.Exit(3)
      return 0
   })
   AddVEH.Call(1, veh)

   orig := make([]byte, CLEN)
   RtlMove.Call(uintptr(unsafe.Pointer(&orig[0])), base+uintptr(srva), CLEN)

   decrypt := func(blob []byte) (uint32, []byte, []byte) {
      clear(gST[:])
      clear(gOUT[:])
      copy(gKB[:], prv)
      gCB = append(gCB[:0], blob...)
      a := gARG[:0x38]
      binary.LittleEndian.PutUint64(a[0x00:], 3)
      binary.LittleEndian.PutUint64(a[0x08:], uint64(base)+uint64(desc))
      binary.LittleEndian.PutUint64(a[0x10:], uint64(uintptr(unsafe.Pointer(&gST[0]))))
      binary.LittleEndian.PutUint32(a[0x18:], 0)
      binary.LittleEndian.PutUint64(a[0x1C:], uint64(uintptr(unsafe.Pointer(&gKB[0]))))
      binary.LittleEndian.PutUint32(a[0x24:], 0x41)
      binary.LittleEndian.PutUint64(a[0x28:], uint64(uintptr(unsafe.Pointer(&gCB[0]))))
      binary.LittleEndian.PutUint64(a[0x30:], uint64(uintptr(unsafe.Pointer(&gOUT[0]))))
      r, _, _ := NtQuery.Call(0xB9, uintptr(unsafe.Pointer(&a[0])), 0x38, 0)
      return uint32(r), append([]byte(nil), gST[:4]...), append([]byte(nil), gOUT[:0x20]...)
   }

   for _, nn := range lics {
      blob, err := os.ReadFile(filepath.Join(ORACLE, fmt.Sprintf("lic_%02x.blob", nn)))
      if err != nil {
         continue
      }
      rc, sd, res := decrypt(blob)
      fmt.Printf("CTRL %02x rc=0x%08x st=%x %x\n", nn, rc, sd, res)
      for mm := 0; mm < 16; mm++ {
         wr(uint32(srva), bytes.Repeat([]byte{byte(mm)}, CLEN))
         rc, sd, res := decrypt(blob)
         wr(uint32(srva), orig)
         fmt.Printf("OUT %02x %02x rc=0x%08x st=%x %x\n", nn, mm, rc, sd, res)
      }
   }
   os.Exit(0)
}

type blk struct{ desc, fo, rva, size uint32 }

// findConsumer returns the heap-exec descriptor owning the unique size-check
// site, so the driver does not have to look it up a second time.
func findConsumer(img []byte, heaps []blk) (blk, []int, bool) {
   var sites []int
   for i := 0; ; {
      j := bytes.Index(img[i:], PAT)
      if j < 0 {
         break
      }
      sites = append(sites, i+j)
      i += j + 1
   }
   if len(sites) != 1 {
      return blk{}, sites, false
   }
   var owner blk
   found := false
   for _, h := range heaps {
      if h.size != 0 && h.rva <= uint32(sites[0]) && uint32(sites[0]) < h.rva+h.size {
         owner, found = h, true
      }
   }
   return owner, sites, found
}

type exceptionPointers struct {
   Record  *exceptionRecord
   Context uintptr
}

// EXCEPTION_RECORD truncated after ExceptionAddress (+0x10): those are the only
// two fields read, and nothing past them is dereferenced.
type exceptionRecord struct {
   Code    uint32
   Flags   uint32
   Prev    uintptr
   Address uintptr
}

type sec struct{ va, rs, rp uint32 }

type sweep struct {
   outs     map[int]map[int]string
   meta     []string
   fault    string
   loadfail string
   rc       int
}

func run(setrva uint32, lics []int) sweep {
   exe, _ := os.Executable()
   ps := make([]string, len(lics))
   for i, x := range lics {
      ps[i] = fmt.Sprintf("%02x", x)
   }
   ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
   defer cancel()
   cmd := exec.CommandContext(ctx, exe, "--sweep",
      fmt.Sprintf("0x%x", setrva), fmt.Sprintf("0x%x", gDesc), strings.Join(ps, ","))
   var so bytes.Buffer
   cmd.Stdout = &so
   err := cmd.Run()

   r := sweep{outs: map[int]map[int]string{}}
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
         nn, _ := strconv.ParseInt(f[1], 16, 64)
         mm, _ := strconv.ParseInt(f[2], 16, 64)
         if r.outs[int(nn)] == nil {
            r.outs[int(nn)] = map[int]string{}
         }
         r.outs[int(nn)][int(mm)] = f[len(f)-1]
      }
   }
   return r
}

// end of 3-derive-map.go
