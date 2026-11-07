//go:build windows

// 4-derive-plain.go
//
// Stage 4: extracted.enc.prv -> extracted.enc.plain
//
//   stage 1  prv[0x00:0x20]  --stage-1 routine-->  OBF
//   stage 2  OBF (mutated in place) --stage-2 routine-->  mut
//   stage 3  mut   --64 per-nibble bijection subtables-->  mapped
//   stage 4  mapped --16-entry permutation from oracle_map.json-->  plain
//
//   Proven by d*G == extracted.enc.pub. Nothing is written unless it holds.
//
// No address here is hardcoded. Both stage routines are selected at runtime by
// walking the code graph outward from the 0x41-byte key consumer; the public key
// decides which (stage 1, stage 2) pairing is real.
//
// Inputs   testdata/{extracted.enc.prv, extracted.enc.pub, wbtool_img.bin,
//          oracle_map.json}
// Output   testdata/{extracted.enc.plain, derive_plain.txt}
//
// Every child prints rc and status for every call, rejects included, so "wrong
// routine" and "never called" are distinguishable. The VEH fault line carries
// the stage tag ("S1 FAULT" / "S2 FAULT") the driver filters on, so a fault is
// never recorded as "no output".
//
// Pitfalls:
//   - The stage routines' own blocks must be LEFT CIPHERTEXT. They are heap-exec,
//     so the kernel decrypts each exactly once during the op=3 call.
//   - Segment blocks must still be patched, or the helpers the stages call are
//     ciphertext and the call faults. PREP=carve is the correct middle.
//   - PREP is overlap-safe by default: it patches segment spans but subtracts the
//     heap-exec blocks. wbtool_img.bin holds DECRYPTED code at those RVAs, so
//     copying it over a block the kernel will decrypt again yields garbage.
//     PREP=full and PREP=none are selectable so the three can be compared.
//   - A fault is reported with code, address, signed offset, module and bytes,
//     then hard-exits via os.Exit; neither the Go runtime nor ctypes unwinds out
//     of a VEH callback.
//   - On failure a localization matrix runs automatically: each candidate with
//     real inputs, then zeroed inputs, to separate a data-dependent fault from a
//     structural one.

package main

import (
   "bytes"
   "cmp"
   "context"
   "crypto/ecdh"
   "crypto/sha256"
   "encoding/binary"
   "encoding/hex"
   "encoding/json"
   "fmt"
   "math/big"
   "os"
   "os/exec"
   "path/filepath"
   "runtime"
   "slices"
   "sort"
   "strconv"
   "strings"
   "syscall"
   "time"
   "unsafe"
)

const (
   dataDir = "testdata"
   dllPath = `C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll`
   rwx     = 0x40
   timeout = 300 * time.Second
   tol     = 0x20
   winSz   = 0x400
   maxHops = 5
   maxBlk  = 400
)

var (
   prvPath = data("extracted.enc.prv")
   pubPath = data("extracted.enc.pub")
   outPath = data("extracted.enc.plain")
   logPath = data("derive_plain.txt")
   imgPath = data("wbtool_img.bin")
   mapPath = data("oracle_map.json")

   pattern = []byte{0x83, 0x79, 0x14, 0x41} // cmp dword ptr [rcx+0x14], 0x41
   z4      [4]byte
   z32     = make([]byte, 0x20)

   kernel32 = syscall.NewLazyDLL("kernel32.dll")
   ntdll    = syscall.NewLazyDLL("ntdll.dll")

   procLoadLibraryW = kernel32.NewProc("LoadLibraryW")
   procVirtualProt  = kernel32.NewProc("VirtualProtect")
   procMappedName   = kernel32.NewProc("K32GetMappedFileNameW")
   procAddVEH       = kernel32.NewProc("AddVectoredExceptionHandler")
   procNtQuery      = ntdll.NewProc("NtQuerySystemInformation")
)

// One trial, one process.
//
//   --s1 <desc> [prep]
//   --s2 <desc> <obfhex> [prep] [variant]
//
// variant 0 real inputs / 1 zero out-buffer / 2 all zero / 3 no second size

var (
   faultBase uintptr
   faultSay  func(string)
)

func census(fb []byte, secs []section, sizeImg uint32) ([]span, []heapExec) {
   var seg []span
   var heaps []heapExec
   seen := map[uint32]bool{}

   for _, s := range secs {
      lo := int(s.rp)
      hi := min(int(s.rp)+int(s.rs), len(fb))
      if hi <= lo {
         continue
      }
      b := fb[lo:hi]
      for off := 0; off < len(b)-0x40; off += 4 {
         size := u32(b, off+0x20)
         if size < 0x40 || size > 0x200000 || off+int(size) > len(b) {
            continue
         }
         sum := sha256.Sum256(b[off+0x20 : off+int(size)])
         if !bytes.Equal(sum[:], b[off:off+32]) {
            continue
         }
         if size == 0xF0 {
            heaps = append(heaps, heapExec{
               desc: s.va + uint32(off),
               rva:  u32(b, off+0x34) & 0x0FFFFFFF,
               size: u32(b, off+0x38) & 0x0FFFFFFF,
            })
            continue
         }
         for k, o := 0, off+0xF4; k < (int(size)-0xF4)/0xC; k, o = k+1, o+0xC {
            rva, sz := u32(b, o+4), u32(b, o+8)
            if rva < 0x1000 || sz < 8 || seen[rva] || uint64(rva)+uint64(sz) > uint64(sizeImg) {
               continue
            }
            seen[rva] = true
            seg = append(seg, span{rva, sz})
         }
      }
   }
   return seg, heaps
}

func data(n string) string {
   return filepath.Join(dataDir, n)
}

func driver() {
   var lines []string
   say := func(f string, a ...any) {
      s := fmt.Sprintf(f, a...)
      lines = append(lines, s)
      fmt.Println(s)
   }
   die := func(f string, a ...any) {
      say("FATAL: "+f, a...)
      _ = os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
      os.Exit(1)
   }
   show := func(r result) string {
      if r.line != "" {
         return r.line
      }
      return fmt.Sprintf("<%s> rc=%d", r.kind, r.rc)
   }

   for _, f := range []string{mapPath, imgPath, prvPath, pubPath} {
      if st, err := os.Stat(f); err != nil || st.IsDir() {
         die("missing %s", f)
      }
   }

   in, err := loadInputs()
   if err != nil {
      die("%v", err)
   }

   vals := make([]int, 0, 16)
   for _, v := range in.mapt {
      vals = append(vals, v)
   }
   slices.Sort(vals)
   if len(vals) != 16 {
      die("oracle_map.json is not a 16-entry permutation")
   }
   for i, v := range vals {
      if v != i {
         die("oracle_map.json is not a 16-entry permutation")
      }
   }
   if in.cluster < 0x1000 {
      die("oracle_map.json cluster RVA 0x%x looks invalid", in.cluster)
   }

   sum := sha256.Sum256(in.fb)
   say("dll    %s", dllPath)
   say("sha256 %x", sum)
   say("image  %s  (%d bytes, SizeOfImage 0x%x)", imgPath, len(in.img), in.sizeImg)
   say("prv    %s  (%d bytes, variant 0x%02x %%3=%d)",
      prvPath, len(in.prv), in.prv[0x40], in.prv[0x40]%3)
   say("pub    %s", pubPath)
   say("cluster 0x%06x  (from %s)", in.cluster, mapPath)
   if in.magic != "" {
      say("magic  %s", in.magic)
   }
   say("")

   ov := 0
   for _, s := range in.seg {
      if len(in.carve(s.rva, s.size)) != 1 {
         ov++
      }
   }
   say("spans intersecting heap-exec blocks: %d of %d", ov, len(in.seg))
   say("")

   heapDesc := make(map[uint32]heapExec, len(in.heaps))
   for _, h := range in.heaps {
      heapDesc[h.desc] = h
   }
   descKeys := make([]uint32, 0, len(heapDesc))
   for d := range heapDesc {
      descKeys = append(descKeys, d)
   }
   slices.Sort(descKeys)

   say("heap-exec descriptors %d", len(heapDesc))
   say("")

   blockOf := func(rva int) (dv, code, n uint32, ok bool) {
      for _, d := range descKeys {
         h := heapDesc[d]
         if int(h.rva) <= rva && rva < int(h.rva+h.size) {
            return d, h.rva, h.size, true
         }
      }
      return 0, 0, 0, false
   }
   matchDesc := func(t int) (uint32, bool) {
      var best uint32
      found := false
      for _, d := range descKeys {
         dist := max(int(d)-t, t-int(d))
         if dist > tol {
            continue
         }
         if !found || dist < max(int(best)-t, t-int(best)) {
            best = d
            found = true
         }
      }
      return best, found
   }

   sites := bytes.Count(in.img, pattern)
   say("key-consumer size-check sites: %d at 0x%x", sites, bytes.Index(in.img, pattern))
   if sites != 1 {
      die("expected exactly one 'cmp dword ptr [rcx+0x14], 0x41' in the image")
   }

   dv0, c0, n0, ok := blockOf(bytes.Index(in.img, pattern))
   if !ok {
      die("no heap-exec block owns the size check")
   }
   say("key consumer: descriptor 0x%06x  code 0x%06x+0x%x", dv0, c0, n0)
   say("")

   // walk the code graph outward from the key consumer
   cand := map[uint32]bool{}
   visited := map[[2]int]bool{}
   frontier := [][2]int{{int(c0), int(n0)}}

   for depth := 0; len(frontier) > 0 && depth < maxHops && len(visited) < maxBlk; {
      depth++
      var nxt [][2]int

      for _, b := range frontier {
         if visited[b] {
            continue
         }
         visited[b] = true

         hi := min(b[0]+b[1], len(in.img)-8)
         for o := max(0x1000, b[0]); o < hi; o++ {
            var t int
            switch {
            case (in.img[o] == 0x48 || in.img[o] == 0x4C) && in.img[o+1] == 0x8D:
               switch in.img[o+2] {
               case 5, 0xD, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D:
                  t = o + 7 + int(int32(u32(in.img, o+3)))
               default:
                  continue
               }
            case in.img[o] == 0xE8 || in.img[o] == 0xE9:
               t = o + 5 + int(int32(u32(in.img, o+1)))
            default:
               continue
            }

            if m, ok := matchDesc(t); ok {
               cand[m] = true
               continue
            }
            if _, c, n, ok := blockOf(t); ok {
               nxt = append(nxt, [2]int{int(c), int(n)})
            } else if t >= 0x1000 && t < len(in.img)-0x40 {
               nxt = append(nxt, [2]int{t, min(winSz, len(in.img)-t)})
            }
         }
      }

      say("  hop %d: blocks %d -> descriptors %d, next %d",
         depth, len(frontier), len(cand), len(nxt))
      frontier = nxt
   }

   candList := make([]uint32, 0, len(cand))
   for d := range cand {
      candList = append(candList, d)
   }
   slices.Sort(candList)

   say("stage candidates: %#x", candList)
   say("")
   if len(candList) == 0 {
      die("no stage candidates - the lea/call idiom differs on this build")
   }

   exe, err := os.Executable()
   if err != nil {
      die("cannot locate own executable: %v", err)
   }

   obfs := map[uint32]string{}
   say("phase 1: stage-1 candidates (PREP=carve)")
   for _, d := range candList {
      r := runChild(exe, []string{"--s1", fmt.Sprintf("0x%x", d), "carve"})
      say("  s1 0x%06x code 0x%06x: %s", d, heapDesc[d].rva, show(r))
      if r.stderr != "" {
         say("      stderr: %s", r.stderr)
      }
      if w := strings.Fields(r.line); r.kind == "OK" && len(w) > 2 {
         obfs[d] = w[2]
      }
   }
   say("")
   say("stage-1 candidates that produced an OBF: %d", len(obfs))
   say("")
   if len(obfs) == 0 {
      die("no candidate produced an OBF - stage 1 is not in the candidate set")
   }

   obfList := make([]string, 0, len(obfs))
   for _, v := range obfs {
      obfList = append(obfList, v)
   }
   slices.Sort(obfList)

   var found []string
   nFault, nReject := 0, 0

   say("phase 2: stage-2 pairing (PREP=carve, variant 0)")
   for _, d1 := range descKeys {
      obf, ok := obfs[d1]
      if !ok {
         continue
      }
      for _, d2 := range candList {
         r := runChild(exe, []string{"--s2", fmt.Sprintf("0x%x", d2), obf, "carve", "0"})
         switch r.kind {
         case "MATCH":
            if found == nil {
               w := strings.Fields(r.line)
               found = []string{
                  strconv.FormatUint(uint64(d1), 10),
                  strconv.FormatUint(uint64(d2), 10),
                  obf,
                  strings.TrimPrefix(w[3], "mut="),
                  strings.TrimPrefix(w[4], "mapped="),
                  strings.TrimPrefix(w[5], "plain="),
               }
            }
         case "FAULT":
            nFault++
         case "REJECT":
            nReject++
            continue
         }
         say("  s2 0x%06x code 0x%06x: %s", d2, heapDesc[d2].rva, show(r))
         if r.stderr != "" {
            say("      stderr: %s", r.stderr)
         }
      }
   }

   match := 0
   if found != nil {
      match = 1
   }
   say("")
   say("summary: MATCH %d  FAULT %d  REJECT %d  of %d attempts",
      match, nFault, nReject, len(obfs)*len(candList))
   say("")

   if found == nil {
      say("no pairing reproduced the public key - localizing")
      say("")
      say("  A: variant 0 (real OBF, real out-buffer, ln 0x30)")
      say("  B: variant 1 (real OBF, ZERO out-buffer)  -> data dependence")
      say("  C: variant 2 (all inputs zero)            -> structural vs data")
      say("  D: variant 3 (ln 0x2C, no second size)    -> arg-length dependence")
      say("")
      say("  %-10s%-10s%-8s%-8s%-8s%-8s%s", "cand", "code", "A", "B", "C", "D", "note")

      obf := obfList[0]
      firstReject := candList[0]
      seenReject := false

      for _, d := range candList {
         row := make([]string, 4)
         var notes []string
         for v := range row {
            r := runChild(exe, []string{
               "--s2", fmt.Sprintf("0x%x", d), obf, "carve", strconv.Itoa(v),
            })
            row[v] = r.kind
            if r.stderr != "" {
               notes = append(notes, fmt.Sprintf("v%d stderr %s", v, r.stderr))
            }
         }
         if !seenReject && row[0] == "REJECT" {
            firstReject = d
            seenReject = true
         }
         say("  %-10s%-10s%-8s%-8s%-8s%-8s%s",
            fmt.Sprintf("0x%x", d),
            fmt.Sprintf("0x%x", heapDesc[d].rva),
            row[0], row[1], row[2], row[3],
            strings.Join(notes, "; "))
      }

      say("")
      say("  reading the matrix")
      say("    A=FAULT B=FAULT C=FAULT  -> structural: the routine is wrong, or the")
      say("                                image state is wrong (try PREP=full/none)")
      say("    A=FAULT B=MATCH/NOMATCH  -> data-dependent: the OBF or prv[0x20:0x40]")
      say("                                drives a bad index/shift in stage 2")
      say("    A=FAULT D=REJECT         -> arg-length dependent: ln 0x30 is required")
      say("                                and the routine rejects it anyway")
      say("    all REJECT               -> the routine is not stage 2 on this build")
      say("")
      say("  prep sensitivity for the best stage-2-looking candidate")

      for _, prep := range []string{"full", "carve", "none"} {
         r := runChild(exe, []string{
            "--s2", fmt.Sprintf("0x%x", firstReject), obf, prep, "0",
         })
         say("    PREP=%-6s 0x%06x: %s", prep, firstReject, show(r))
         if r.stderr != "" {
            say("        stderr: %s", r.stderr)
         }
      }
      die("no (stage 1, stage 2) pairing reproduced extracted.enc.pub")
   }

   plain, err := hex.DecodeString(found[5])
   if err != nil {
      die("bad plain hex from child: %v", err)
   }
   s1, _ := strconv.ParseUint(found[0], 10, 32)
   s2, _ := strconv.ParseUint(found[1], 10, 32)

   say("stage 1   0x%06x  (descriptor 0x%06x)", heapDesc[uint32(s1)].rva, s1)
   say("OBF       %s", found[2])
   say("stage 2   0x%06x  (descriptor 0x%06x)", heapDesc[uint32(s2)].rva, s2)
   say("in-mutated %s", found[3])
   say("mapped    %s", found[4])
   say("plain     %s", found[5])

   d := new(big.Int).SetBytes(plain)
   priv, err := ecdh.P256().NewPrivateKey(d.FillBytes(make([]byte, 32)))
   if err != nil {
      die("derived scalar out of range: %v", err)
   }
   if got := priv.PublicKey().Bytes()[1:]; !bytes.Equal(got, in.pub) {
      die("scalar does not reproduce %s\n  got  %x\n  want %x", pubPath, got, in.pub)
   }

   say("pubkey    MATCH")
   if err := os.WriteFile(outPath, plain, 0o644); err != nil {
      die("write %s: %v", outPath, err)
   }
   psum := sha256.Sum256(plain)
   say("written   %s  (%d bytes)  sha256 %x", outPath, len(plain), psum)

   _ = os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func lastLine(s string) string {
   ls := strings.Split(strings.TrimRight(s, "\r\n"), "\n")
   return strings.TrimSpace(ls[len(ls)-1])
}

func loadMap(raw []byte) (map[int]int, uint32, string, error) {
   var o oracle
   if err := json.Unmarshal(raw, &o); err != nil {
      return nil, 0, "", err
   }
   if o.Map == nil {
      return nil, 0, "", fmt.Errorf("%s is in the old flat format - re-run stage 3", mapPath)
   }
   m := make(map[int]int, len(o.Map))
   for k, v := range o.Map {
      ki, err := strconv.Atoi(k)
      if err != nil {
         return nil, 0, "", fmt.Errorf("%s: bad map key %q", mapPath, k)
      }
      m[ki] = v
   }
   return m, uint32(o.Cluster), o.Magic, nil
}

func main() {
   _ = os.MkdirAll(dataDir, 0o755)

   a := os.Args[1:]
   if len(a) == 0 || (a[0] != "--s1" && a[0] != "--s2") {
      driver()
      return
   }
   if len(a) < 2 {
      fmt.Println("usage: --s1 <desc> [prep] | --s2 <desc> <obfhex> [prep] [variant]")
      os.Exit(2)
   }

   d, err := strconv.ParseUint(a[1], 0, 32)
   if err != nil {
      fmt.Printf("%s ERR bad descriptor %q\n", tag(a[0]), a[1])
      os.Exit(5)
   }

   prep, obf, variant := "carve", "", 0
   if a[0] == "--s1" {
      if len(a) > 2 {
         prep = a[2]
      }
   } else {
      if len(a) < 3 {
         fmt.Println("usage: --s2 <desc> <obfhex> [prep] [variant]")
         os.Exit(2)
      }
      obf = a[2]
      if len(a) > 3 {
         prep = a[3]
      }
      if len(a) > 4 {
         variant, _ = strconv.Atoi(a[4])
      }
   }
   worker(a[0], uint32(d), obf, prep, variant)
}

// onFault is the VEH handler. It never returns.
func onFault(ep uintptr) uintptr {
   er := *(*uintptr)(ptrAt(ep))        // EXCEPTION_POINTERS.ExceptionRecord
   code := *(*uint32)(ptrAt(er))       // ExceptionCode
   ad := *(*uintptr)(ptrAt(er + 0x10)) // ExceptionAddress

   mod := "-"
   var nm [512]uint16
   r, _, _ := procMappedName.Call(^uintptr(0), ad, uintptr(unsafe.Pointer(&nm[0])), 512)
   if r != 0 {
      if s := syscall.UTF16ToString(nm[:]); s != "" {
         mod = s[strings.LastIndexByte(s, '\\')+1:]
      }
   }

   raw := "-"
   if ad != 0 {
      raw = hex.EncodeToString(unsafe.Slice((*byte)(ptrAt(ad)), 16))
   }

   faultSay(fmt.Sprintf(
      "FAULT 0x%08x addr=0x%016x off=%+#x module=%s bytes=%s",
      code, ad, int64(ad)-int64(faultBase), mod, raw,
   ))
   os.Exit(3)
   return 0
}

// ptrAt reinterprets an address the OS handed us as an integer. The direct form
// unsafe.Pointer(u) is rejected by vet's unsafeptr check, which cannot see that
// these integers are mapped addresses, so the write goes through a variable.
func ptrAt(u uintptr) unsafe.Pointer {
   var p unsafe.Pointer
   *(*uintptr)(unsafe.Pointer(&p)) = u
   return p
}

func rawAt(fb []byte, secs []section, rva, n uint32) []byte {
   for _, s := range secs {
      if s.va <= rva && rva < s.va+s.rs {
         if off := int(s.rp) + int(rva-s.va); off+int(n) <= len(fb) {
            return fb[off : off+int(n)]
         }
      }
   }
   return nil
}

func tag(mode string) string {
   if mode == "--s1" {
      return "S1"
   }
   return "S2"
}

func u16(b []byte, o int) uint16 {
   return binary.LittleEndian.Uint16(b[o:])
}

func u32(b []byte, o int) uint32 {
   return binary.LittleEndian.Uint32(b[o:])
}

func worker(mode string, desc uint32, obfHex, prep string, variant int) {
   t := tag(mode)
   say := func(f string, a ...any) {
      fmt.Printf("%s "+f+"\n", append([]any{t}, a...)...)
   }
   defer func() {
      if r := recover(); r != nil {
         say("ERR %v", r)
         os.Exit(5)
      }
   }()

   in, err := loadInputs()
   if err != nil {
      say("ERR %v", err)
      os.Exit(5)
   }

   ptr, err := syscall.UTF16PtrFromString(dllPath)
   if err != nil {
      say("ERR loadlibrary")
      os.Exit(4)
   }
   base, _, _ := procLoadLibraryW.Call(uintptr(unsafe.Pointer(ptr)))
   if base == 0 {
      say("ERR loadlibrary")
      os.Exit(4)
   }

   wr := func(rva uint32, buf []byte) bool {
      p := base + uintptr(rva)
      n := (uintptr(len(buf)) + 0xFFF) &^ 0xFFF
      var old, dummy uint32
      r, _, _ := procVirtualProt.Call(p, n, rwx, uintptr(unsafe.Pointer(&old)))
      if r == 0 {
         return false
      }
      copy(unsafe.Slice((*byte)(ptrAt(p)), len(buf)), buf)
      procVirtualProt.Call(p, n, uintptr(old), uintptr(unsafe.Pointer(&dummy)))
      return true
   }

   patched, skipped := 0, 0
   if prep != "none" {
      for _, s := range in.seg {
         if uint64(s.rva)+uint64(s.size) > uint64(len(in.img)) {
            continue
         }
         c := rawAt(in.fb, in.secs, s.rva, s.size)
         if c == nil || bytes.Equal(in.img[s.rva:s.rva+s.size], c) {
            continue
         }
         runs := []run{{s.rva, s.size}}
         if prep != "full" {
            runs = in.carve(s.rva, s.size)
            if len(runs) == 0 {
               skipped++
            }
         }
         for _, x := range runs {
            if wr(x.start, in.img[x.start:x.start+x.length]) {
               patched++
            } else {
               skipped++
            }
         }
      }
   }
   say("PREP %s patched %d skipped %d", prep, patched, skipped)

   faultBase = base
   faultSay = func(s string) {
      say("%s", s)
   }
   procAddVEH.Call(1, syscall.NewCallback(onFault))

   op3 := func(descRVA, ln uint32, status, key, out []byte, size2 *uint32) uint32 {
      var a [0x40]byte
      binary.LittleEndian.PutUint64(a[0x00:], 3)
      binary.LittleEndian.PutUint64(a[0x08:], uint64(base)+uint64(descRVA))
      binary.LittleEndian.PutUint64(a[0x10:], uint64(uintptr(unsafe.Pointer(&status[0]))))
      binary.LittleEndian.PutUint64(a[0x18:], uint64(uintptr(unsafe.Pointer(&key[0]))))
      binary.LittleEndian.PutUint32(a[0x20:], 0x20)
      binary.LittleEndian.PutUint64(a[0x24:], uint64(uintptr(unsafe.Pointer(&out[0]))))
      if size2 != nil {
         binary.LittleEndian.PutUint32(a[0x2C:], *size2)
      }
      r, _, _ := procNtQuery.Call(0xB9, uintptr(unsafe.Pointer(&a[0])), uintptr(ln), 0)
      runtime.KeepAlive(a)
      runtime.KeepAlive(status)
      runtime.KeepAlive(key)
      runtime.KeepAlive(out)
      return uint32(r)
   }

   if mode == "--s1" {
      st := make([]byte, 0x40)
      kb := make([]byte, 0x40)
      ob := make([]byte, 0x40)
      copy(kb, in.prv[:0x20])

      rc := op3(desc, 0x2C, st, kb, ob, nil)
      sd := st[:4]
      if rc != 0 || !bytes.Equal(sd, z4[:]) || bytes.Equal(ob[:0x20], z32) {
         say("REJECT rc=0x%08x st=%s out=%s",
            rc, hex.EncodeToString(sd), hex.EncodeToString(ob[:0x20]))
      } else {
         say("OK %s", hex.EncodeToString(ob[:0x20]))
      }
      os.Exit(0)
   }

   obf, err := hex.DecodeString(obfHex)
   if err != nil {
      say("ERR %v", err)
      os.Exit(5)
   }

   var in1, in2 []byte
   switch variant {
   case 2:
      in1, in2 = make([]byte, 0x20), make([]byte, 0x20)
   case 1:
      in1, in2 = obf, make([]byte, 0x20)
   default:
      in1, in2 = obf, in.prv[0x20:0x40]
   }

   ln := uint32(0x30)
   if variant == 3 {
      ln = 0x2C
   }

   st2 := make([]byte, 0x40)
   ib := make([]byte, 0x40)
   ob2 := make([]byte, 0x40)
   copy(ib, in1)
   copy(ob2, in2)

   var s2 *uint32
   if variant != 3 {
      v := uint32(0x20)
      s2 = &v
   }

   if rc := op3(desc, ln, st2, ib, ob2, s2); rc != 0 || !bytes.Equal(st2[:4], z4[:]) {
      say("REJECT var=%d rc=0x%08x st=%s", variant, rc, hex.EncodeToString(st2[:4]))
      os.Exit(0)
   }
   mut := ib[:0x20]

   // stage 3: 64 per-nibble subtables, stage 4: 16-entry permutation
   nibs := func(x []byte) []byte {
      ns := make([]byte, 64)
      for i := range ns {
         sh := uint(0)
         if i%2 == 0 {
            sh = 4
         }
         ns[i] = x[i>>1] >> sh & 0xF
      }
      return ns
   }
   pack := func(ns []byte) []byte {
      out := make([]byte, 32)
      for i := 0; i < 64; i += 2 {
         out[i/2] = ns[i]<<4 | ns[i+1]
      }
      return out
   }

   nm := nibs(mut)
   mp := make([]byte, 64)
   for i := range mp {
      mp[i] = in.img[int(in.cluster)+i*16+int(nm[i])]
   }
   mapped := pack(mp)

   nn := nibs(mapped)
   pl := make([]byte, 64)
   for i := range pl {
      v, ok := in.mapt[int(nn[i])]
      if !ok {
         panic(fmt.Sprintf("KeyError: %d", nn[i]))
      }
      pl[i] = byte(v)
   }
   plain := pack(pl)

   d := new(big.Int).SetBytes(plain)
   res := "NOMATCH"
   priv, err := ecdh.P256().NewPrivateKey(d.FillBytes(make([]byte, 32)))
   if err == nil && bytes.Equal(priv.PublicKey().Bytes()[1:], in.pub) {
      res = "MATCH"
   }
   say("%s var=%d mut=%s mapped=%s plain=%s", res, variant,
      hex.EncodeToString(mut),
      hex.EncodeToString(mapped),
      hex.EncodeToString(plain))
   os.Exit(0)
}

type carveFn func(r, s uint32) []run

// makeCarve returns [r, r+s) minus the heap-exec blocks as a list of runs.
func makeCarve(merged []interval) carveFn {
   los := make([]uint32, len(merged))
   for i, m := range merged {
      los[i] = m.lo
   }

   return func(r, s uint32) []run {
      var out []run
      cur, end := r, r+s
      i := max(sort.Search(len(los), func(i int) bool { return los[i] > r })-1, 0)

      for _, m := range merged[i:] {
         if m.hi <= cur {
            continue
         }
         if m.lo >= end {
            break
         }
         if m.lo > cur {
            out = append(out, run{cur, min(m.lo, end) - cur})
         }
         if cur = max(cur, m.hi); cur >= end {
            break
         }
      }
      if cur < end {
         out = append(out, run{cur, end - cur})
      }
      return out
   }
}

type heapExec struct{ desc, rva, size uint32 }

type inputs struct {
   img     []byte
   fb      []byte
   secs    []section
   seg     []span
   heaps   []heapExec
   carve   carveFn
   prv     []byte
   pub     []byte
   mapt    map[int]int
   cluster uint32
   sizeImg uint32
   magic   string
}

func loadInputs() (*inputs, error) {
   in := &inputs{}
   var err error

   if in.img, err = os.ReadFile(imgPath); err != nil {
      return nil, err
   }
   raw, err := os.ReadFile(mapPath)
   if err != nil {
      return nil, err
   }
   if in.mapt, in.cluster, in.magic, err = loadMap(raw); err != nil {
      return nil, err
   }
   if in.prv, err = os.ReadFile(prvPath); err != nil {
      return nil, err
   }
   if len(in.prv) != 0x41 {
      return nil, fmt.Errorf("%s is %d bytes, expected 0x41 (65)", prvPath, len(in.prv))
   }
   pub, err := os.ReadFile(pubPath)
   if err != nil {
      return nil, err
   }
   if len(pub) < 64 {
      return nil, fmt.Errorf("%s: need at least 64 bytes, got %d", pubPath, len(pub))
   }
   in.pub = pub[len(pub)-64:]

   if in.fb, err = os.ReadFile(dllPath); err != nil {
      return nil, err
   }
   in.sizeImg, in.secs = pe(in.fb)
   in.seg, in.heaps = census(in.fb, in.secs, in.sizeImg)
   in.carve = makeCarve(mergeBlocks(in.heaps))
   return in, nil
}

type interval struct{ lo, hi uint32 }

func mergeBlocks(heaps []heapExec) []interval {
   var ps []interval
   for _, h := range heaps {
      if h.size != 0 {
         ps = append(ps, interval{h.rva, h.rva + h.size})
      }
   }
   slices.SortFunc(ps, func(a, b interval) int { return cmp.Compare(a.lo, b.lo) })

   var out []interval
   for _, p := range ps {
      if n := len(out); n > 0 && p.lo <= out[n-1].hi {
         out[n-1].hi = max(out[n-1].hi, p.hi)
         continue
      }
      out = append(out, p)
   }
   return out
}

type oracle struct {
   Map     map[string]int `json:"map"`
   Cluster int            `json:"cluster"`
   Magic   string         `json:"magic"`
}

type result struct {
   kind   string
   line   string
   stderr string
   rc     int
}

func runChild(exe string, args []string) result {
   ctx, cancel := context.WithTimeout(context.Background(), timeout)
   defer cancel()

   cmd := exec.CommandContext(ctx, exe, args...)
   var out, errb bytes.Buffer
   cmd.Stdout = &out
   cmd.Stderr = &errb
   err := cmd.Run()

   if ctx.Err() != nil {
      return result{kind: "TIMEOUT", rc: -1}
   }

   r := result{kind: "NONE"}
   if ee, ok := err.(*exec.ExitError); ok {
      r.rc = ee.ExitCode()
   } else if err != nil {
      r.rc = -1
   }

   pre := tag(args[0]) + " "
   for _, x := range strings.Split(out.String(), "\n") {
      x = strings.TrimSuffix(x, "\r")
      if !strings.HasPrefix(x, pre) {
         continue
      }
      w := strings.Fields(x)
      if len(w) < 2 {
         continue
      }
      switch w[1] {
      case "FAULT":
         r.kind = "FAULT"
         r.line = x
         r.stderr = lastLine(errb.String())
         return r
      case "OK", "REJECT", "MATCH", "NOMATCH", "ERR":
         r.kind = w[1]
         r.line = x
      }
   }
   r.stderr = lastLine(errb.String())
   return r
}

type run struct{ start, length uint32 }

type section struct{ va, rs, rp uint32 }

func pe(fb []byte) (uint32, []section) {
   lf := int(u32(fb, 0x3C))
   n, optsz := int(u16(fb, lf+6)), int(u16(fb, lf+20))
   sizeImg := u32(fb, lf+24+56)
   p, secs := lf+24+optsz, make([]section, n)
   for i := range secs {
      secs[i] = section{va: u32(fb, p+12), rs: u32(fb, p+16), rp: u32(fb, p+20)}
      p += 40
   }
   return sizeImg, secs
}

type span struct{ rva, size uint32 }

// end of 4-derive-plain.go
