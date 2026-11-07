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
// USAGE
//   enc.plain -4
//
//   No flags. Every path above is a constant.
//
//   Trials run in children of this same binary, using positional arguments
//   rather than flags:
//     enc.plain -4 s1 <desc> [prep]
//     enc.plain -4 s2 <desc> <obf> [prep] [variant]
//   (internal; the driver spawns them, nothing else should)
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
   dpDataDir = "testdata"
   dpDLLPath = `C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll`
   dpRWX     = 0x40
   dpTimeout = 300 * time.Second
   dpTol     = 0x20
   dpWinSz   = 0x400
   dpMaxHops = 5
   dpMaxBlk  = 400
)

var (
   dpPrvPath = dpData("extracted.enc.prv")
   dpPubPath = dpData("extracted.enc.pub")
   dpOutPath = dpData("extracted.enc.plain")
   dpLogPath = dpData("derive_plain.txt")
   dpImgPath = dpData("wbtool_img.bin")
   dpMapPath = dpData("oracle_map.json")

   dpPattern = []byte{0x83, 0x79, 0x14, 0x41} // cmp dword ptr [rcx+0x14], 0x41
   dpZ4      [4]byte
   dpZ32     = make([]byte, 0x20)

   dpKernel32 = syscall.NewLazyDLL("kernel32.dll")
   dpNtdll    = syscall.NewLazyDLL("ntdll.dll")

   dpProcLoadLibraryW = dpKernel32.NewProc("LoadLibraryW")
   dpProcVirtualProt  = dpKernel32.NewProc("VirtualProtect")
   dpProcMappedName   = dpKernel32.NewProc("K32GetMappedFileNameW")
   dpProcAddVEH       = dpKernel32.NewProc("AddVectoredExceptionHandler")
   dpProcNtQuery      = dpNtdll.NewProc("NtQuerySystemInformation")
)

// One trial, one process.
//
//   -4 s1 <desc> [prep]
//   -4 s2 <desc> <obf> [prep] [variant]
//
// variant 0 real inputs / 1 zero out-buffer / 2 all zero / 3 no second size

var (
   dpFaultBase uintptr
   dpFaultSay  func(string)
)

func dpCensus(fb []byte, secs []dpSection, sizeImg uint32) ([]dpSpan, []dpHeapExec) {
   var seg []dpSpan
   var heaps []dpHeapExec
   seen := map[uint32]bool{}

   for _, s := range secs {
      lo := int(s.rp)
      hi := min(int(s.rp)+int(s.rs), len(fb))
      if hi <= lo {
         continue
      }
      b := fb[lo:hi]
      for off := 0; off < len(b)-0x40; off += 4 {
         size := dpU32(b, off+0x20)
         if size < 0x40 || size > 0x200000 || off+int(size) > len(b) {
            continue
         }
         sum := sha256.Sum256(b[off+0x20 : off+int(size)])
         if !bytes.Equal(sum[:], b[off:off+32]) {
            continue
         }
         if size == 0xF0 {
            heaps = append(heaps, dpHeapExec{
               desc: s.va + uint32(off),
               rva:  dpU32(b, off+0x34) & 0x0FFFFFFF,
               size: dpU32(b, off+0x38) & 0x0FFFFFFF,
            })
            continue
         }
         for k, o := 0, off+0xF4; k < (int(size)-0xF4)/0xC; k, o = k+1, o+0xC {
            rva, sz := dpU32(b, o+4), dpU32(b, o+8)
            if rva < 0x1000 || sz < 8 || seen[rva] || uint64(rva)+uint64(sz) > uint64(sizeImg) {
               continue
            }
            seen[rva] = true
            seg = append(seg, dpSpan{rva, sz})
         }
      }
   }
   return seg, heaps
}

func dpData(n string) string {
   return filepath.Join(dpDataDir, n)
}

func dpDriver() {
   var lines []string
   say := func(f string, a ...any) {
      s := fmt.Sprintf(f, a...)
      lines = append(lines, s)
      fmt.Println(s)
   }
   die := func(f string, a ...any) {
      say("FATAL: "+f, a...)
      _ = os.WriteFile(dpLogPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
      os.Exit(1)
   }
   show := func(r dpResult) string {
      if r.line != "" {
         return r.line
      }
      return fmt.Sprintf("<%s> rc=%d", r.kind, r.rc)
   }

   for _, f := range []string{dpMapPath, dpImgPath, dpPrvPath, dpPubPath} {
      if st, err := os.Stat(f); err != nil || st.IsDir() {
         die("missing %s", f)
      }
   }

   in, err := dpLoadInputs()
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
   say("dll    %s", dpDLLPath)
   say("sha256 %x", sum)
   say("image  %s  (%d bytes, SizeOfImage 0x%x)", dpImgPath, len(in.img), in.sizeImg)
   say("prv    %s  (%d bytes, variant 0x%02x %%3=%d)",
      dpPrvPath, len(in.prv), in.prv[0x40], in.prv[0x40]%3)
   say("pub    %s", dpPubPath)
   say("cluster 0x%06x  (from %s)", in.cluster, dpMapPath)
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

   heapDesc := make(map[uint32]dpHeapExec, len(in.heaps))
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
         if dist > dpTol {
            continue
         }
         if !found || dist < max(int(best)-t, t-int(best)) {
            best = d
            found = true
         }
      }
      return best, found
   }

   sites := bytes.Count(in.img, dpPattern)
   say("key-consumer size-check sites: %d at 0x%x", sites, bytes.Index(in.img, dpPattern))
   if sites != 1 {
      die("expected exactly one 'cmp dword ptr [rcx+0x14], 0x41' in the image")
   }

   dv0, c0, n0, ok := blockOf(bytes.Index(in.img, dpPattern))
   if !ok {
      die("no heap-exec block owns the size check")
   }
   say("key consumer: descriptor 0x%06x  code 0x%06x+0x%x", dv0, c0, n0)
   say("")

   // walk the code graph outward from the key consumer
   cand := map[uint32]bool{}
   visited := map[[2]int]bool{}
   frontier := [][2]int{{int(c0), int(n0)}}

   for depth := 0; len(frontier) > 0 && depth < dpMaxHops && len(visited) < dpMaxBlk; {
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
                  t = o + 7 + int(int32(dpU32(in.img, o+3)))
               default:
                  continue
               }
            case in.img[o] == 0xE8 || in.img[o] == 0xE9:
               t = o + 5 + int(int32(dpU32(in.img, o+1)))
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
               nxt = append(nxt, [2]int{t, min(dpWinSz, len(in.img)-t)})
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
      r := dpRunChild(exe, "s1", fmt.Sprintf("0x%x", d), "carve")
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
         r := dpRunChild(exe, "s2",
            fmt.Sprintf("0x%x", d2), obf, "carve", "0")
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
            r := dpRunChild(exe, "s2",
               fmt.Sprintf("0x%x", d), obf, "carve", strconv.Itoa(v))
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
         r := dpRunChild(exe, "s2", fmt.Sprintf("0x%x", firstReject), obf, prep, "0")
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
      die("scalar does not reproduce %s\n  got  %x\n  want %x", dpPubPath, got, in.pub)
   }

   say("pubkey    MATCH")
   if err := os.WriteFile(dpOutPath, plain, 0o644); err != nil {
      die("write %s: %v", dpOutPath, err)
   }
   psum := sha256.Sum256(plain)
   say("written   %s  (%d bytes)  sha256 %x", dpOutPath, len(plain), psum)

   _ = os.WriteFile(dpLogPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func dpLastLine(s string) string {
   ls := strings.Split(strings.TrimRight(s, "\r\n"), "\n")
   return strings.TrimSpace(ls[len(ls)-1])
}

func dpLoadMap(raw []byte) (map[int]int, uint32, string, error) {
   var o dpOracle
   if err := json.Unmarshal(raw, &o); err != nil {
      return nil, 0, "", err
   }
   if o.Map == nil {
      return nil, 0, "", fmt.Errorf("%s is in the old flat format - re-run stage 3", dpMapPath)
   }
   m := make(map[int]int, len(o.Map))
   for k, v := range o.Map {
      ki, err := strconv.Atoi(k)
      if err != nil {
         return nil, 0, "", fmt.Errorf("%s: bad map key %q", dpMapPath, k)
      }
      m[ki] = v
   }
   return m, uint32(o.Cluster), o.Magic, nil
}

// dpOnFault is the VEH handler. It never returns.
func dpOnFault(ep uintptr) uintptr {
   er := *(*uintptr)(dpPtrAt(ep))        // EXCEPTION_POINTERS.ExceptionRecord
   code := *(*uint32)(dpPtrAt(er))       // ExceptionCode
   ad := *(*uintptr)(dpPtrAt(er + 0x10)) // ExceptionAddress

   mod := "-"
   var nm [512]uint16
   r, _, _ := dpProcMappedName.Call(^uintptr(0), ad, uintptr(unsafe.Pointer(&nm[0])), 512)
   if r != 0 {
      if s := syscall.UTF16ToString(nm[:]); s != "" {
         mod = s[strings.LastIndexByte(s, '\\')+1:]
      }
   }

   raw := "-"
   if ad != 0 {
      raw = hex.EncodeToString(unsafe.Slice((*byte)(dpPtrAt(ad)), 16))
   }

   dpFaultSay(fmt.Sprintf(
      "FAULT 0x%08x addr=0x%016x off=%+#x module=%s bytes=%s",
      code, ad, int64(ad)-int64(dpFaultBase), mod, raw,
   ))
   os.Exit(3)
   return 0
}

// dpPtrAt reinterprets an address the OS handed us as an integer. The direct
// form unsafe.Pointer(u) is rejected by vet's unsafeptr check, which cannot see
// that these integers are mapped addresses, so the write goes through a
// variable.
func dpPtrAt(u uintptr) unsafe.Pointer {
   var p unsafe.Pointer
   *(*uintptr)(unsafe.Pointer(&p)) = u
   return p
}

func dpRawAt(fb []byte, secs []dpSection, rva, n uint32) []byte {
   for _, s := range secs {
      if s.va <= rva && rva < s.va+s.rs {
         if off := int(s.rp) + int(rva-s.va); off+int(n) <= len(fb) {
            return fb[off : off+int(n)]
         }
      }
   }
   return nil
}

func dpTag(mode string) string {
   if mode == "s1" {
      return "S1"
   }
   return "S2"
}

func dpU16(b []byte, o int) uint16 {
   return binary.LittleEndian.Uint16(b[o:])
}

func dpU32(b []byte, o int) uint32 {
   return binary.LittleEndian.Uint32(b[o:])
}

func dpWorker(mode string, desc uint32, obfHex, prep string, variant int) {
   t := dpTag(mode)
   say := func(f string, a ...any) {
      fmt.Printf("%s "+f+"\n", append([]any{t}, a...)...)
   }
   defer func() {
      if r := recover(); r != nil {
         say("ERR %v", r)
         os.Exit(5)
      }
   }()

   in, err := dpLoadInputs()
   if err != nil {
      say("ERR %v", err)
      os.Exit(5)
   }

   ptr, err := syscall.UTF16PtrFromString(dpDLLPath)
   if err != nil {
      say("ERR loadlibrary")
      os.Exit(4)
   }
   base, _, _ := dpProcLoadLibraryW.Call(uintptr(unsafe.Pointer(ptr)))
   if base == 0 {
      say("ERR loadlibrary")
      os.Exit(4)
   }

   wr := func(rva uint32, buf []byte) bool {
      p := base + uintptr(rva)
      n := (uintptr(len(buf)) + 0xFFF) &^ 0xFFF
      var old, dummy uint32
      r, _, _ := dpProcVirtualProt.Call(p, n, dpRWX, uintptr(unsafe.Pointer(&old)))
      if r == 0 {
         return false
      }
      copy(unsafe.Slice((*byte)(dpPtrAt(p)), len(buf)), buf)
      dpProcVirtualProt.Call(p, n, uintptr(old), uintptr(unsafe.Pointer(&dummy)))
      return true
   }

   patched, skipped := 0, 0
   if prep != "none" {
      for _, s := range in.seg {
         if uint64(s.rva)+uint64(s.size) > uint64(len(in.img)) {
            continue
         }
         c := dpRawAt(in.fb, in.secs, s.rva, s.size)
         if c == nil || bytes.Equal(in.img[s.rva:s.rva+s.size], c) {
            continue
         }
         runs := []dpRun{{s.rva, s.size}}
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

   dpFaultBase = base
   dpFaultSay = func(s string) {
      say("%s", s)
   }
   dpProcAddVEH.Call(1, syscall.NewCallback(dpOnFault))

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
      r, _, _ := dpProcNtQuery.Call(0xB9, uintptr(unsafe.Pointer(&a[0])), uintptr(ln), 0)
      runtime.KeepAlive(a)
      runtime.KeepAlive(status)
      runtime.KeepAlive(key)
      runtime.KeepAlive(out)
      return uint32(r)
   }

   if mode == "s1" {
      st := make([]byte, 0x40)
      kb := make([]byte, 0x40)
      ob := make([]byte, 0x40)
      copy(kb, in.prv[:0x20])

      rc := op3(desc, 0x2C, st, kb, ob, nil)
      sd := st[:4]
      if rc != 0 || !bytes.Equal(sd, dpZ4[:]) || bytes.Equal(ob[:0x20], dpZ32) {
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

   if rc := op3(desc, ln, st2, ib, ob2, s2); rc != 0 || !bytes.Equal(st2[:4], dpZ4[:]) {
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

// --- stage entry point ------------------------------------------------------

func stageDerivePlain(args []string) int {
   // Internal trial modes. Positional, so the command line surface stays at
   // exactly -1 -2 -3 -4.
   if len(args) > 0 && (args[0] == "s1" || args[0] == "s2") {
      mode, a := args[0], args[1:]
      if len(a) < 1 {
         fmt.Fprintln(os.Stderr,
            "usage: enc.plain -4 s1 <desc> [prep] | enc.plain -4 s2 <desc> <obf> [prep] [variant]")
         return 2
      }
      d, err := strconv.ParseUint(a[0], 0, 32)
      if err != nil {
         fmt.Printf("%s ERR bad descriptor %q\n", dpTag(mode), a[0])
         return 5
      }

      prep, obf, variant := "carve", "", 0
      if mode == "s1" {
         if len(a) > 1 {
            prep = a[1]
         }
      } else {
         if len(a) < 2 {
            fmt.Fprintln(os.Stderr,
               "usage: enc.plain -4 s2 <desc> <obf> [prep] [variant]")
            return 2
         }
         obf = a[1]
         if len(a) > 2 {
            prep = a[2]
         }
         if len(a) > 3 {
            variant, _ = strconv.Atoi(a[3])
         }
      }
      dpWorker(mode, uint32(d), obf, prep, variant)
      return 0
   }
   if len(args) > 0 {
      fmt.Fprintf(os.Stderr, "enc.plain -4: unexpected argument %q\n", args[0])
      return 2
   }

   dpDriver()
   return 0
}

type dpCarveFn func(r, s uint32) []dpRun

// dpMakeCarve returns [r, r+s) minus the heap-exec blocks as a list of runs.
func dpMakeCarve(merged []dpInterval) dpCarveFn {
   los := make([]uint32, len(merged))
   for i, m := range merged {
      los[i] = m.lo
   }

   return func(r, s uint32) []dpRun {
      var out []dpRun
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
            out = append(out, dpRun{cur, min(m.lo, end) - cur})
         }
         if cur = max(cur, m.hi); cur >= end {
            break
         }
      }
      if cur < end {
         out = append(out, dpRun{cur, end - cur})
      }
      return out
   }
}

type dpHeapExec struct {
   desc uint32
   rva  uint32
   size uint32
}

type dpInputs struct {
   img     []byte
   fb      []byte
   secs    []dpSection
   seg     []dpSpan
   heaps   []dpHeapExec
   carve   dpCarveFn
   prv     []byte
   pub     []byte
   mapt    map[int]int
   cluster uint32
   sizeImg uint32
   magic   string
}

func dpLoadInputs() (*dpInputs, error) {
   in := &dpInputs{}
   var err error

   if in.img, err = os.ReadFile(dpImgPath); err != nil {
      return nil, err
   }
   raw, err := os.ReadFile(dpMapPath)
   if err != nil {
      return nil, err
   }
   if in.mapt, in.cluster, in.magic, err = dpLoadMap(raw); err != nil {
      return nil, err
   }
   if in.prv, err = os.ReadFile(dpPrvPath); err != nil {
      return nil, err
   }
   if len(in.prv) != 0x41 {
      return nil, fmt.Errorf("%s is %d bytes, expected 0x41 (65)", dpPrvPath, len(in.prv))
   }
   pub, err := os.ReadFile(dpPubPath)
   if err != nil {
      return nil, err
   }
   if len(pub) < 64 {
      return nil, fmt.Errorf("%s: need at least 64 bytes, got %d", dpPubPath, len(pub))
   }
   in.pub = pub[len(pub)-64:]

   if in.fb, err = os.ReadFile(dpDLLPath); err != nil {
      return nil, err
   }
   in.sizeImg, in.secs = dpPE(in.fb)
   in.seg, in.heaps = dpCensus(in.fb, in.secs, in.sizeImg)
   in.carve = dpMakeCarve(dpMergeBlocks(in.heaps))
   return in, nil
}

type dpInterval struct {
   lo uint32
   hi uint32
}

func dpMergeBlocks(heaps []dpHeapExec) []dpInterval {
   var ps []dpInterval
   for _, h := range heaps {
      if h.size != 0 {
         ps = append(ps, dpInterval{h.rva, h.rva + h.size})
      }
   }
   slices.SortFunc(ps, func(a, b dpInterval) int { return cmp.Compare(a.lo, b.lo) })

   var out []dpInterval
   for _, p := range ps {
      if n := len(out); n > 0 && p.lo <= out[n-1].hi {
         out[n-1].hi = max(out[n-1].hi, p.hi)
         continue
      }
      out = append(out, p)
   }
   return out
}

type dpOracle struct {
   Map     map[string]int `json:"map"`
   Cluster int            `json:"cluster"`
   Magic   string         `json:"magic"`
}

type dpResult struct {
   kind   string
   line   string
   stderr string
   rc     int
}

// dpRunChild spawns one trial as `exe -4 <mode> <args...>`. Positional, so no
// flag is ever involved.
func dpRunChild(exe, mode string, args ...string) dpResult {
   ctx, cancel := context.WithTimeout(context.Background(), dpTimeout)
   defer cancel()

   cmd := exec.CommandContext(ctx, exe, append([]string{"-4", mode}, args...)...)
   var out, errb bytes.Buffer
   cmd.Stdout = &out
   cmd.Stderr = &errb
   err := cmd.Run()

   if ctx.Err() != nil {
      return dpResult{kind: "TIMEOUT", rc: -1}
   }

   r := dpResult{kind: "NONE"}
   if ee, ok := err.(*exec.ExitError); ok {
      r.rc = ee.ExitCode()
   } else if err != nil {
      r.rc = -1
   }

   pre := dpTag(mode) + " "
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
         r.stderr = dpLastLine(errb.String())
         return r
      case "OK", "REJECT", "MATCH", "NOMATCH", "ERR":
         r.kind = w[1]
         r.line = x
      }
   }
   r.stderr = dpLastLine(errb.String())
   return r
}

type dpRun struct {
   start  uint32
   length uint32
}

type dpSection struct {
   va uint32
   rs uint32
   rp uint32
}

func dpPE(fb []byte) (uint32, []dpSection) {
   lf := int(dpU32(fb, 0x3C))
   n, optsz := int(dpU16(fb, lf+6)), int(dpU16(fb, lf+20))
   sizeImg := dpU32(fb, lf+24+56)
   p, secs := lf+24+optsz, make([]dpSection, n)
   for i := range secs {
      secs[i] = dpSection{va: dpU32(fb, p+12), rs: dpU32(fb, p+16), rp: dpU32(fb, p+20)}
      p += 40
   }
   return sizeImg, secs
}

type dpSpan struct {
   rva  uint32
   size uint32
}

// end of 4-derive-plain.go
