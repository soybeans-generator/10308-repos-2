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
   CBLK  = 16
   CN    = 64
   CLEN  = 0x400
   RWX   = 0x40
   KBLEN = 0x48
)

// --- paths -------------------------------------------------------------------
// Every input and every output lives under testdata/. There is deliberately no
// fallback to the current directory: a stale extracted.enc.prv sitting next to
// the binary can no longer be picked up in place of the intended one.
const DATA = "testdata"

const DLL = `C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll`

var (
   IMG    = data("wbtool_img.bin")
   PRVF   = data("extracted.enc.prv")
   ORACLE = data("oracle")
   OUTF   = data("oracle_map.json")
   LOG    = data("derive_map.txt")
)

var (
   W10 = mustHex("a77bece491a87ebcd8a2c62856b165b3" +
      "3ad2572cf88bdae3ddc79be816be3185")
   W11 = mustHex("c3cd57691eff156c95d946d534121dfb" +
      "81738adb5b4bb4223faad89cbb459bec")
)

// ================================ worker =====================================

var (
   kernel32 = syscall.NewLazyDLL("kernel32.dll")
   ntdll    = syscall.NewLazyDLL("ntdll.dll")

   procLoadLibraryW = kernel32.NewProc("LoadLibraryW")
   procVirtualProt  = kernel32.NewProc("VirtualProtect")
   procGetMapped    = kernel32.NewProc("K32GetMappedFileNameW")
   procAddVEH       = kernel32.NewProc("AddVectoredExceptionHandler")
   procNtQuery      = ntdll.NewProc("NtQuerySystemInformation")
   procRtlMove      = ntdll.NewProc("RtlMoveMemory")
)

// Static, never-moved scratch storage handed to native code.
var (
   gST  [0x40]byte
   gOUT [0x100]byte
   gKB  [KBLEN]byte
   gARG [0x40]byte
   gNM  [512]uint16
   gCB  []byte
)

var PAT = []byte{0x83, 0x79, 0x14, 0x41} // cmp dword ptr [rcx+0x14], 0x41

var SENT = append([]byte("HELLO MICROSOFT!"), make([]byte, 16)...)

var gDesc uint32

// ================================ driver =====================================

var logLines []string

var vehKeep uintptr

func allDistinct(b []byte) bool {
   var seen [256]bool
   for _, c := range b {
      if seen[c] {
         return false
      }
      seen[c] = true
   }
   return true
}

func census(fb []byte, secs []section, sizeImg uint32) ([]seg, []heapBlk, []span) {
   var segs []seg
   var heaps []heapBlk
   var spans []span

   for _, s := range secs {
      b := clampSlice(fb, s.rp, s.rs)
      limit := len(b) - 0x40
      if limit < 0 {
         limit = 0
      }
      for off := 0; off < limit; off += 4 {
         size := u32(b, off+0x20)
         if size < 0x40 || size > 0x200000 || uint64(off)+uint64(size) > uint64(len(b)) {
            continue
         }
         sum := sha256.Sum256(b[off+0x20 : off+int(size)])
         if !bytes.Equal(sum[:], b[off:off+32]) {
            continue
         }
         if size == 0xF0 {
            heaps = append(heaps, heapBlk{
               desc: s.va + uint32(off),
               fo:   s.rp + uint32(off),
               rva:  u32(b, off+0x34) & 0x0FFFFFFF,
               size: u32(b, off+0x38) & 0x0FFFFFFF,
            })
         } else {
            segs = append(segs, seg{
               desc: s.va + uint32(off),
               fo:   s.rp + uint32(off),
               size: size,
            })
         }
      }
   }

   for _, sg := range segs { // per descriptor, NOT deduped by RVA
      b := clampSlice(fb, sg.fo, sg.size)
      kmax := (int(sg.size) - 0xF4) / 0xC
      if kmax < 0 {
         kmax = 0
      }
      for k := 0; k < kmax; k++ {
         o := 0xF4 + k*0xC
         rva, sz := u32(b, o+4), u32(b, o+8)
         if rva >= 0x1000 && sz >= 8 && uint64(rva)+uint64(sz) <= uint64(sizeImg) {
            spans = append(spans, span{rva: rva, size: sz})
         }
      }
   }
   return segs, heaps, spans
}

func clampSlice(b []byte, off, n uint32) []byte {
   end := uint64(off) + uint64(n)
   if end > uint64(len(b)) {
      end = uint64(len(b))
   }
   if uint64(off) > end {
      return b[len(b):]
   }
   return b[off:end]
}

func commas(n int) string {
   s := strconv.Itoa(n)
   neg := strings.HasPrefix(s, "-")
   if neg {
      s = s[1:]
   }
   var out []byte
   for i := 0; i < len(s); i++ {
      if i > 0 && (len(s)-i)%3 == 0 {
         out = append(out, ',')
      }
      out = append(out, s[i])
   }
   if neg {
      return "-" + string(out)
   }
   return string(out)
}

func data(name string) string { return filepath.Join(DATA, name) }

func die(msg string) {
   logf("FATAL: %s", msg)
   _ = os.WriteFile(LOG, []byte(strings.Join(logLines, "\n")+"\n"), 0o644)
   os.Exit(1)
}

// explain prints why a worker produced nothing usable.
func explain(r sweepResult) string {
   var b strings.Builder
   if r.loadfail != "" {
      b.WriteString(r.loadfail)
   }
   if s := strings.TrimSpace(r.stderr); s != "" {
      if b.Len() > 0 {
         b.WriteString(" | ")
      }
      b.WriteString("stderr: " + firstLines(s, 6))
   }
   if b.Len() == 0 {
      fmt.Fprintf(&b, "rc %d, no output", r.rc)
   }
   return b.String()
}

func findConsumer(img []byte, heaps []heapBlk) (uint32, []int, bool) {
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
      return 0, sites, false
   }
   var owner uint32
   found := false
   for _, h := range heaps {
      if h.size != 0 && h.rva <= uint32(sites[0]) && uint32(sites[0]) < h.rva+h.size {
         owner = h.desc
         found = true
      }
   }
   return owner, sites, found
}

func firstLines(s string, n int) string {
   lines := strings.Split(s, "\n")
   if len(lines) > n {
      lines = lines[:n]
   }
   return strings.Join(lines, " / ")
}

// loadfail reports why the worker could not start. It goes to stdout so the
// driver can print it; a bare exit code is useless.
func loadfail(format string, a ...any) {
   fmt.Printf("LOADFAIL "+format+"\n", a...)
   os.Exit(4)
}

func logf(format string, a ...any) { logln(fmt.Sprintf(format, a...)) }

func logln(s string) {
   logLines = append(logLines, s)
   fmt.Println(s)
}

func main() {
   _ = os.MkdirAll(DATA, 0o755)
   if len(os.Args) > 1 && os.Args[1] == "--sweep" {
      runWorker()
      return
   }
   runDriver()
}

func minU32(a, b uint32) uint32 {
   if a < b {
      return a
   }
   return b
}

func mustHex(s string) []byte {
   b, err := hex.DecodeString(s)
   if err != nil {
      panic(err)
   }
   return b
}

func pe(fb []byte) (uint32, []section) {
   lf := int(u32(fb, 0x3C))
   nsec := int(u16(fb, lf+6))
   optsz := int(u16(fb, lf+20))
   sizeImg := u32(fb, lf+24+56)
   p := lf + 24 + optsz
   secs := make([]section, 0, nsec)
   for i := 0; i < nsec; i++ {
      va := u32(fb, p+12)
      rs := u32(fb, p+16)
      rp := u32(fb, p+20)
      secs = append(secs, section{va: va, rs: rs, rp: rp})
      p += 40
   }
   return sizeImg, secs
}

func pyHexList(xs []int) string {
   parts := make([]string, len(xs))
   for i, x := range xs {
      parts[i] = fmt.Sprintf("0x%x", x)
   }
   return "[" + strings.Join(parts, ", ") + "]"
}

func pyIntDict(m map[int]int, keys []int) string {
   var sb strings.Builder
   sb.WriteString("{")
   for i, k := range keys {
      if i > 0 {
         sb.WriteString(", ")
      }
      sb.WriteString(fmt.Sprintf("%d: %d", k, m[k]))
   }
   sb.WriteString("}")
   return sb.String()
}

func pyIntList(xs []int) string {
   parts := make([]string, len(xs))
   for i, x := range xs {
      parts[i] = strconv.Itoa(x)
   }
   return "[" + strings.Join(parts, ", ") + "]"
}

func rawAt(fb []byte, secs []section, rva, n uint32) []byte {
   for _, s := range secs {
      if s.va <= rva && rva < s.va+s.rs &&
         uint64(s.rp)+uint64(rva-s.va)+uint64(n) <= uint64(len(fb)) {
         o := s.rp + (rva - s.va)
         return fb[o : o+n]
      }
   }
   return nil
}

func runDriver() {
   for _, f := range []string{IMG, PRVF} {
      if st, err := os.Stat(f); err != nil || st.IsDir() {
         die("missing " + f)
      }
   }
   if st, err := os.Stat(ORACLE); err != nil || !st.IsDir() {
      die(fmt.Sprintf("missing %s\\ - run make-oracle first", ORACLE))
   }

   fb, err := os.ReadFile(DLL)
   if err != nil {
      die("cannot read " + DLL + ": " + err.Error())
   }
   img, err := os.ReadFile(IMG)
   if err != nil {
      die("cannot read " + IMG + ": " + err.Error())
   }

   sizeImg, secs := pe(fb)
   segs, heaps, spans := census(fb, secs, sizeImg)

   sum := sha256.Sum256(fb)
   logf("dll      %s", DLL)
   logf("sha256   %s", hex.EncodeToString(sum[:]))
   logf("size     %s   SizeOfImage 0x%x", commas(len(fb)), sizeImg)
   logf("image    %s  %s bytes", IMG, commas(len(img)))
   logf("segments %d  heap-exec %d  spans %d", len(segs), len(heaps), len(spans))
   logln("")

   SETS := findSets(img)
   logf("bijection sets: %d", len(SETS))
   for _, s := range SETS {
      end := s.rva + 16
      if end > uint32(len(img)) {
         end = uint32(len(img))
      }
      logf("  %s  0x%06x  %s", s.name, s.rva, hex.EncodeToString(img[s.rva:end]))
   }
   logln("")
   if len(SETS) == 0 {
      die("no permutation sets found - is wbtool_img.bin decrypted?")
   }

   DESC, sites, ok := findConsumer(img, heaps)
   logf("size-check sites: %s", pyHexList(sites))
   if !ok {
      die(fmt.Sprintf("consumer not unique (%d sites)", len(sites)))
   }
   var h heapBlk
   for _, x := range heaps {
      if x.desc == DESC {
         h = x
         break
      }
   }
   logf("consumer descriptor 0x%06x  code 0x%06x+0x%x", DESC, h.rva, h.size)
   logln("")
   gDesc = DESC

   // ---- phase 1: live set + magic, using three licences
   P1 := []int{1, 2, 3}
   logf("phase 1: %d sets x licences %s", len(SETS), pyIntList(P1))
   logf("%-6s%-12s%-26s%-8s%s", "set", "rva", "distinct", "shared", "verdict")

   var (
      liveName  string
      liveRVA   uint32
      haveLive  bool
      magicHex  string
      liveTable sweepResult
   )

   for _, s := range SETS {
      r := sweep(s.rva, P1)
      if r.loadfail != "" {
         die("worker cannot start: " + explain(r))
      }
      if r.fault != "" {
         logf("%-6s0x%06x  %s", s.name, s.rva, r.fault)
         continue
      }
      missing := false
      for _, nn := range P1 {
         if _, ok := r.outs[nn]; !ok {
            missing = true
            break
         }
      }
      if missing {
         logf("%-6s0x%06x  incomplete (%s)", s.name, s.rva, explain(r))
         continue
      }

      sets := make(map[int]map[string]bool, len(P1))
      distinct := make(map[int]int, len(P1))
      for _, nn := range P1 {
         m := make(map[string]bool, len(r.outs[nn]))
         for _, v := range r.outs[nn] {
            m[v] = true
         }
         sets[nn] = m
         distinct[nn] = len(m)
      }
      shared := map[string]bool{}
      for v := range sets[P1[0]] {
         shared[v] = true
      }
      for _, nn := range P1[1:] {
         for v := range shared {
            if !sets[nn][v] {
               delete(shared, v)
            }
         }
      }
      minD := 1 << 30
      for _, nn := range P1 {
         if distinct[nn] < minD {
            minD = distinct[nn]
         }
      }

      verdict := "not live"
      if len(shared) == 1 && minD > 1 {
         verdict = "LIVE"
      }
      logf("%-6s0x%06x  %-26s%-8d%s", s.name, s.rva,
         pyIntDict(distinct, P1), len(shared), verdict)

      if verdict == "LIVE" {
         if haveLive {
            die(fmt.Sprintf("two live sets: %s and %s", liveName, s.name))
         }
         haveLive = true
         liveName, liveRVA, liveTable = s.name, s.rva, r
         for v := range shared {
            magicHex = v
         }
      }
   }
   logln("")

   if !haveLive {
      logln("no set produced a shared plaintext across licences.")
      logln("")
      logln("That rules out both wrong-magic and wrong-live-set: if the sentinel were")
      logln("ever produced, the shared value would appear. So the sentinel is never")
      logln("reached at all, which points at the blob/ECC encoding rather than at the")
      logln("tables. Check, in order:")
      logln("  1. lic_NN.blob point order - C1||C2 vs C2||C1. The oracle writes")
      logln("     C1=(rG) then C2=(M+rQ); a build that reads C2 first never lands on M.")
      logln("  2. Whether the consumer really is the 0x41 licence consumer on this")
      logln("     build. Compare the 'distinct' column: all-1 means the patch has no")
      logln("     effect on the output, so that descriptor is not reading the table.")
      logln("  3. Whether prv[0x40]%3 selects a routine family whose table is not among")
      logln("     the discovered sets - the VARIANT line above records the value.")
      die("no live set")
   }

   mh, err := hex.DecodeString(magicHex)
   if err != nil {
      die("worker produced a non-hex sentinel output")
   }
   n := len(mh)
   if len(SENT) < n {
      n = len(SENT)
   }
   MAGIC := make([]byte, n)
   for i := 0; i < n; i++ {
      MAGIC[i] = mh[i] ^ SENT[i]
   }

   logf("live set   %s 0x%06x", liveName, liveRVA)
   logf("magic      %s", hex.EncodeToString(MAGIC))
   switch {
   case bytes.Equal(MAGIC, W10):
      logln("           == the Windows 10 sequence")
   case bytes.Equal(MAGIC, W11):
      logln("           == the Windows 11 sequence")
   default:
      logln("           == NEITHER published sequence: this build uses a third one,")
      logln("              which is why a hardcoded W10 constant would never match.")
   }
   logln("")
   for _, m := range liveTable.meta {
      logf("  %s", m)
   }

   // ---- phase 2: full permutation on the live set
   logln("")
   logln("phase 2: full permutation on the live set")
   r := sweep(liveRVA, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
   if r.loadfail != "" {
      die("worker cannot start: " + explain(r))
   }
   if r.fault != "" {
      die(r.fault)
   }
   for nn := 1; nn < 16; nn++ {
      if _, ok := r.outs[nn]; !ok {
         die("incomplete sweep: " + explain(r))
      }
   }

   TARGET := magicHex // the shared sentinel output, as hex
   MAP := map[int]int{}
   for nn := 1; nn < 16; nn++ {
      var hits []int
      for mm, v := range r.outs[nn] {
         if v == TARGET {
            hits = append(hits, mm)
         }
      }
      if len(hits) != 1 {
         die(fmt.Sprintf("nibble 0x%x: %d hits, expected 1", nn, len(hits)))
      }
      sort.Ints(hits)
      mm := hits[0]
      if prev, used := MAP[mm]; used {
         die(fmt.Sprintf("nibble 0x%x: mapped 0x%x already used by real 0x%x", nn, mm, prev))
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
      die(fmt.Sprintf("expected one leftover, got %s", pyHexList(left)))
   }
   MAP[left[0]] = 0
   logf("  leftover mapped 0x%x -> real 0x0", left[0])
   logln("")

   vals := make([]int, 0, len(MAP))
   for _, v := range MAP {
      vals = append(vals, v)
   }
   sort.Ints(vals)
   for i, v := range vals {
      if i != v {
         die("not a bijection")
      }
   }

   logln("[MAP]  mapped -> real")
   for m := 0; m < 16; m++ {
      logf("  %x -> %x", m, MAP[m])
   }

   out := struct {
      Cluster uint32         `json:"cluster"`
      Magic   string         `json:"magic"`
      Map     map[string]int `json:"map"`
   }{
      Cluster: liveRVA,
      Magic:   hex.EncodeToString(MAGIC),
      Map:     map[string]int{},
   }
   for k, v := range MAP {
      out.Map[strconv.Itoa(k)] = v
   }
   blob, err := json.MarshalIndent(out, "", "  ")
   if err != nil {
      die("json: " + err.Error())
   }
   if err := os.WriteFile(OUTF, blob, 0o644); err != nil {
      die("cannot write " + OUTF + ": " + err.Error())
   }
   logln("")
   logf("written %s", OUTF)
   _ = os.WriteFile(LOG, []byte(strings.Join(logLines, "\n")+"\n"), 0o644)
}

func runWorker() {
   if len(os.Args) < 5 {
      fmt.Println("usage: <exe> --sweep SETRVA DESC LICS")
      os.Exit(2)
   }
   setRVA64, err := strconv.ParseInt(os.Args[2], 0, 64)
   if err != nil {
      loadfail("bad setrva %q: %v", os.Args[2], err)
   }
   desc64, err := strconv.ParseInt(os.Args[3], 0, 64)
   if err != nil {
      loadfail("bad desc %q: %v", os.Args[3], err)
   }
   var lics []int
   for _, x := range strings.Split(os.Args[4], ",") {
      v, err := strconv.ParseInt(strings.TrimSpace(x), 16, 64)
      if err != nil {
         loadfail("bad licence %q: %v", x, err)
      }
      lics = append(lics, int(v))
   }
   setRVA := uint32(setRVA64)
   desc := uint32(desc64)

   fb, err := os.ReadFile(DLL)
   if err != nil {
      loadfail("read dll: %v", err)
   }
   img, err := os.ReadFile(IMG)
   if err != nil {
      loadfail("read image %s: %v", IMG, err)
   }
   prvRaw, err := os.ReadFile(PRVF)
   if err != nil {
      loadfail("read %s: %v", PRVF, err)
   }
   // create_string_buffer(PRV, 0x48) zero-pads a short .prv; do the same
   // rather than refusing to run.
   var kb [KBLEN]byte
   copy(kb[:], prvRaw)

   sizeImg, secs := pe(fb)
   _, heaps, spans := census(fb, secs, sizeImg)

   dllPtr, err := syscall.UTF16PtrFromString(DLL)
   if err != nil {
      loadfail("utf16 dll path: %v", err)
   }
   bp, _, lerr := procLoadLibraryW.Call(uintptr(unsafe.Pointer(dllPtr)))
   base := uintptr(bp)
   if base == 0 {
      loadfail("LoadLibraryW %s: %v", DLL, lerr)
   }

   // The module base stays a plain uintptr: it is only ever handed to native
   // code as an address argument, and memory traffic goes through RtlMoveMemory
   // so no uintptr is ever turned back into a Go pointer.
   wr := func(rva uint32, buf []byte) bool {
      if len(buf) == 0 {
         return true
      }
      span := (len(buf) + 0xFFF) &^ 0xFFF
      addr := base + uintptr(rva)
      var old, dummy uint32
      r, _, _ := procVirtualProt.Call(addr, uintptr(span), uintptr(RWX),
         uintptr(unsafe.Pointer(&old)))
      if r == 0 {
         return false
      }
      procRtlMove.Call(addr, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
      procVirtualProt.Call(addr, uintptr(span), uintptr(old),
         uintptr(unsafe.Pointer(&dummy)))
      return true
   }

   // --- prep: patch segment plaintext, but never over a heap-exec block.
   // The kernel decrypts those itself on op=3; pre-filling them causes a
   // double decrypt and the routine executes garbage.
   type rng struct{ lo, hi uint32 }
   var blocks []rng
   for _, h := range heaps {
      if h.size != 0 {
         blocks = append(blocks, rng{h.rva, h.rva + h.size})
      }
   }
   sort.Slice(blocks, func(i, j int) bool { return blocks[i].lo < blocks[j].lo })

   var merged []rng
   for _, b := range blocks {
      if n := len(merged); n > 0 && b.lo <= merged[n-1].hi {
         if b.hi > merged[n-1].hi {
            merged[n-1].hi = b.hi
         }
      } else {
         merged = append(merged, b)
      }
   }
   los := make([]uint32, len(merged))
   for i, b := range merged {
      los[i] = b.lo
   }

   // carve subtracts heap-exec blocks from [r,r+s); returns remaining runs.
   carve := func(r, s uint32) [][2]uint32 {
      cur, e := r, r+s
      var runs [][2]uint32
      i := 0
      for j, lo := range los {
         if lo <= r {
            i = j
         } else {
            break
         }
      }
      for _, blk := range merged[i:] {
         lo, hi := blk.lo, blk.hi
         if hi <= cur {
            continue
         }
         if lo >= e {
            break
         }
         if lo > cur {
            runs = append(runs, [2]uint32{cur, minU32(lo, e)})
         }
         if hi > cur {
            cur = hi
         }
         if cur >= e {
            break
         }
      }
      if cur < e {
         runs = append(runs, [2]uint32{cur, e})
      }
      out := make([][2]uint32, 0, len(runs))
      for _, run := range runs {
         if run[1] > run[0] {
            out = append(out, [2]uint32{run[0], run[1] - run[0]})
         }
      }
      return out
   }

   patched, skipped := 0, 0
   for _, sp := range spans {
      if uint64(sp.rva)+uint64(sp.size) > uint64(len(img)) {
         continue
      }
      c := rawAt(fb, secs, sp.rva, sp.size)
      if c == nil || bytes.Equal(img[sp.rva:sp.rva+sp.size], c) {
         continue
      }
      for _, run := range carve(sp.rva, sp.size) {
         a, n := run[0], run[1]
         if wr(a, img[a:a+n]) {
            patched++
         } else {
            skipped++
         }
      }
   }
   fmt.Printf("PATCHED %d skipped %d\n", patched, skipped)
   fmt.Printf("VARIANT prv[0x40]=0x%02x %%3=%d\n", kb[0x40], int(kb[0x40])%3)

   vehKeep = syscall.NewCallback(func(ep *exceptionPointers) uintptr {
      var code uint32
      var ad uintptr
      if ep != nil && ep.Record != nil {
         code = ep.Record.Code
         ad = ep.Record.Address
      }
      mod := "-"
      if r, _, _ := procGetMapped.Call(^uintptr(0), ad,
         uintptr(unsafe.Pointer(&gNM[0])), 512); r != 0 {
         if s := syscall.UTF16ToString(gNM[:]); s != "" {
            if idx := strings.LastIndex(s, `\`); idx >= 0 {
               mod = s[idx+1:]
            } else {
               mod = s
            }
         }
      }
      fmt.Printf("FAULT 0x%08x addr=0x%016x off=%+#x module=%s\n",
         code, ad, int64(ad)-int64(base), mod)
      os.Exit(3)
      return 0
   })
   procAddVEH.Call(1, vehKeep)

   orig := make([]byte, CLEN)
   procRtlMove.Call(uintptr(unsafe.Pointer(&orig[0])), base+uintptr(setRVA), CLEN)

   decrypt := func(blob []byte) (uint32, []byte, []byte) {
      zero(gST[:])
      zero(gOUT[:])
      copy(gKB[:], kb[:])
      if cap(gCB) < len(blob) {
         gCB = make([]byte, len(blob))
      } else {
         gCB = gCB[:len(blob)]
      }
      copy(gCB, blob)
      zero(gARG[:])

      binary.LittleEndian.PutUint64(gARG[0x00:], 3)
      binary.LittleEndian.PutUint64(gARG[0x08:], uint64(base)+uint64(desc))
      binary.LittleEndian.PutUint64(gARG[0x10:], uint64(uintptr(unsafe.Pointer(&gST[0]))))
      binary.LittleEndian.PutUint32(gARG[0x18:], 0)
      binary.LittleEndian.PutUint64(gARG[0x1C:], uint64(uintptr(unsafe.Pointer(&gKB[0]))))
      binary.LittleEndian.PutUint32(gARG[0x24:], 0x41)
      binary.LittleEndian.PutUint64(gARG[0x28:], uint64(uintptr(unsafe.Pointer(&gCB[0]))))
      binary.LittleEndian.PutUint64(gARG[0x30:], uint64(uintptr(unsafe.Pointer(&gOUT[0]))))

      r, _, _ := procNtQuery.Call(0xB9, uintptr(unsafe.Pointer(&gARG[0])), 0x38, 0)
      sd := append([]byte(nil), gST[:4]...)
      res := append([]byte(nil), gOUT[:0x20]...)
      return uint32(r), sd, res
   }

   for _, nn := range lics {
      blob, err := os.ReadFile(filepath.Join(ORACLE, fmt.Sprintf("lic_%02x.blob", nn)))
      if err != nil {
         fmt.Printf("CTRL %02x rc=0x%08x st= %s\n", nn, 0, "")
         continue
      }
      rc, sd, res := decrypt(blob)
      fmt.Printf("CTRL %02x rc=0x%08x st=%s %s\n", nn, rc,
         hex.EncodeToString(sd), hex.EncodeToString(res))
      for mm := 0; mm < 16; mm++ {
         wr(setRVA, bytes.Repeat([]byte{byte(mm)}, CLEN))
         rc, sd, res := decrypt(blob)
         wr(setRVA, orig)
         fmt.Printf("OUT %02x %02x rc=0x%08x st=%s %s\n", nn, mm, rc,
            hex.EncodeToString(sd), hex.EncodeToString(res))
      }
   }
   os.Exit(0)
}

func u16(b []byte, o int) uint16 { return binary.LittleEndian.Uint16(b[o:]) }
func u32(b []byte, o int) uint32 { return binary.LittleEndian.Uint32(b[o:]) }

func zero(b []byte) {
   for i := range b {
      b[i] = 0
   }
}

type exceptionPointers struct {
   Record  *exceptionRecord
   Context uintptr
}

// EXCEPTION_RECORD: Code +0x00, Flags +0x04, ExceptionRecord +0x08,
// ExceptionAddress +0x10, NumberParameters +0x18, Information +0x20.
type exceptionRecord struct {
   Code     uint32
   Flags    uint32
   Prev     uintptr
   Address  uintptr
   NumParam uint32
   _        uint32
   Info     [15]uintptr
}
type heapBlk struct{ desc, fo, rva, size uint32 }

// ---------------------------------------------------------------- PE / census

type section struct{ va, rs, rp uint32 }
type seg struct{ desc, fo, size uint32 }
type setRec struct {
   name string
   rva  uint32
}

// findSets mirrors re.finditer(rb"[\x00-\x0f]{0x400,}") plus the sliding
// bijection test, and returns "setN" / rva pairs sorted by rva.
func findSets(img []byte) []setRec {
   var found []int
   i := 0
   for i < len(img) {
      if img[i] > 0x0f {
         i++
         continue
      }
      lo := i
      for i < len(img) && img[i] <= 0x0f {
         i++
      }
      hi := i
      o := lo
      for o+CLEN <= hi {
         if !allDistinct(img[o : o+CBLK]) {
            o++
            continue
         }
         ok := true
         for k := 0; k < CN; k++ {
            if !allDistinct(img[o+k*CBLK : o+(k+1)*CBLK]) {
               ok = false
               break
            }
         }
         if ok {
            found = append(found, o)
            o += CLEN
         } else {
            o++
         }
      }
   }
   sort.Ints(found)
   out := make([]setRec, len(found))
   for i, rva := range found {
      out[i] = setRec{name: fmt.Sprintf("set%d", i), rva: uint32(rva)}
   }
   return out
}

type span struct{ rva, size uint32 }

type sweepResult struct {
   ctrl     map[int]string
   outs     map[int]map[int]string
   meta     []string
   fault    string
   loadfail string
   stderr   string
   rc       int
}

func sweep(setrva uint32, lics []int) sweepResult {
   exe, err := os.Executable()
   if err != nil {
      die("cannot locate own executable: " + err.Error())
   }
   parts := make([]string, len(lics))
   for i, x := range lics {
      parts[i] = fmt.Sprintf("%02x", x)
   }

   ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
   defer cancel()
   cmd := exec.CommandContext(ctx, exe,
      "--sweep", fmt.Sprintf("0x%x", setrva), fmt.Sprintf("0x%x", gDesc),
      strings.Join(parts, ","))

   var stdout, stderr bytes.Buffer
   cmd.Stdout = &stdout
   cmd.Stderr = &stderr
   err = cmd.Run()

   rc := 0
   if err != nil {
      if ee, ok := err.(*exec.ExitError); ok {
         rc = ee.ExitCode()
      } else {
         rc = -1
      }
   }

   res := sweepResult{
      ctrl:   map[int]string{},
      outs:   map[int]map[int]string{},
      rc:     rc,
      stderr: stderr.String(),
   }
   for _, line := range strings.Split(stdout.String(), "\n") {
      f := strings.Fields(line)
      if len(f) == 0 {
         continue
      }
      switch f[0] {
      case "PATCHED", "VARIANT":
         res.meta = append(res.meta, line)
      case "LOADFAIL":
         res.loadfail = strings.TrimSpace(line)
      case "CTRL":
         if len(f) >= 2 {
            nn, _ := strconv.ParseInt(f[1], 16, 64)
            res.ctrl[int(nn)] = f[len(f)-1]
         }
      case "OUT":
         if len(f) >= 3 {
            nn, _ := strconv.ParseInt(f[1], 16, 64)
            mm, _ := strconv.ParseInt(f[2], 16, 64)
            if res.outs[int(nn)] == nil {
               res.outs[int(nn)] = map[int]string{}
            }
            res.outs[int(nn)][int(mm)] = f[len(f)-1]
         }
      case "FAULT":
         res.fault = line
      }
   }
   return res
}

// end of 3-derive-map.go
