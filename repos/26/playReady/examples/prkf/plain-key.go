// plainkey.go begin
//go:build windows

// prkf -7: extracted.enc.prv -> extracted.enc.plain
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
// Inputs   encPrvPath, encPubPath, imgPath, mapPath
// Output   encPlainPath, plainLogPath
//
// USAGE
//   prkf -7
//
//   No flags of its own. Every path above is a manifest entry in main.go.
//
//   Trials run in children of this same binary, using positional arguments
//   rather than flags:
//     prkf -7 s1 <desc> [prep]
//     prkf -7 s2 <desc> <obf> [prep] [variant]
//   (internal; the driver spawns them, nothing else should)
//
// Every child prints rc and status for every call, rejects included, so "wrong
// routine" and "never called" are distinguishable. The VEH fault line carries
// the stage tag ("S1 FAULT" / "S2 FAULT") the driver filters on, so a fault is
// never recorded as "no output".
//
// EXIT CODES
//   Nothing here calls os.Exit. dpDriver returns 1 on failure and 0 on success.
//   The trial child itself is in child.go and returns 0 (a RESULT line), 4
//   (module load), 5 (bad input or a recovered panic) or 6 (no VEH). The trial
//   log is written by dpDriver's deferred flush, so no failure path can leave it
//   unwritten.
//
// The descriptor format, the PE census, the span lookup, the block carving, the
// page patch and the fault handler are shared with -5 and -6 and live in
// warbird.go.
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
//   - If AddVectoredExceptionHandler returns NULL the child reports ERR and exits
//     6 instead of running unprotected, because with no handler a fault is a
//     plain process death the driver can only record as NONE.
//   - On failure a localization matrix runs automatically: each candidate with
//     real inputs, then zeroed inputs, to separate a data-dependent fault from a
//     structural one.
//
// GLOBALS
//   dpPattern is the only one: the size-check signature is read in three places
//   here and nowhere else. The tuning numbers - timeout, tolerance, window,
//   hop and block caps - are locals next to the code that uses them, and the
//   trial child's ABI is in child.go.

package main

import (
   "bytes"
   "context"
   "crypto/ecdh"
   "crypto/sha256"
   "encoding/hex"
   "encoding/json"
   "fmt"
   "math/big"
   "os"
   "os/exec"
   "slices"
   "strconv"
   "strings"
   "time"
)

var dpPattern = []byte{0x83, 0x79, 0x14, 0x41} // cmp dword ptr [rcx+0x14], 0x41

// One trial, one process.
//
//   -7 s1 <desc> [prep]
//   -7 s2 <desc> <obf> [prep] [variant]
//
// variant 0 real inputs / 1 zero out-buffer / 2 all zero / 3 no second size

func dpDriver() (code int) {
   const (
      tol     = 0x20 // a lea/call target this close to a descriptor VA is that descriptor
      winSz   = 0x400
      maxHops = 5
      maxBlk  = 400
   )

   var lines []string
   say := func(f string, a ...any) {
      s := fmt.Sprintf(f, a...)
      lines = append(lines, s)
      fmt.Println(s)
   }
   fail := func(f string, a ...any) int {
      say("FATAL: "+f, a...)
      return 1
   }
   // The trial log is the only record of how the pairing was found, so it is
   // flushed by a defer rather than by each exit: a failure path that forgot to
   // write it would leave the run with no evidence at all.
   defer func() {
      if err := os.WriteFile(plainLogPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
         fmt.Fprintf(os.Stderr, "prkf -7: %s: %v\n", plainLogPath, err)
         if code == 0 {
            code = 1
         }
      }
   }()
   show := func(r dpResult) string {
      if r.line != "" {
         return r.line
      }
      return fmt.Sprintf("<%s> rc=%d", r.kind, r.rc)
   }

   for _, f := range []string{mapPath, imgPath, encPrvPath, encPubPath} {
      if st, err := os.Stat(f); err != nil || st.IsDir() {
         return fail("missing %s", f)
      }
   }

   in, err := dpLoadInputs()
   if err != nil {
      return fail("%v", err)
   }

   // A 16-entry permutation: 16 keys in 0..15, each mapping to a distinct value.
   // Both halves are checked because stage 4 indexes mapt with a nibble and a
   // missing key would panic mid-child instead of failing here.
   if len(in.mapt) != 16 {
      return fail("oracle_map.json is not a 16-entry permutation (%d entries)", len(in.mapt))
   }
   var seenVal uint32
   for k, v := range in.mapt {
      if k < 0 || k > 15 || v < 0 || v > 15 {
         return fail("oracle_map.json: %d -> %d is out of range", k, v)
      }
      seenVal |= 1 << uint(v)
   }
   if seenVal != 0xFFFF {
      return fail("oracle_map.json is not a 16-entry permutation (repeated value)")
   }
   if in.cluster < 0x1000 {
      return fail("oracle_map.json cluster RVA 0x%x looks invalid", in.cluster)
   }

   sum := sha256.Sum256(in.fb)
   say("dll    %s", dllPath)
   say("sha256 %x", sum)
   say("image  %s  (%d bytes, SizeOfImage 0x%x)", imgPath, len(in.img), in.sizeImg)
   say("prv    %s  (%d bytes, variant 0x%02x %%3=%d)",
      encPrvPath, len(in.prv), in.prv[0x40], in.prv[0x40]%3)
   say("pub    %s", encPubPath)
   say("cluster 0x%06x  (from %s)", in.cluster, mapPath)
   if in.magic != "" {
      say("magic  %s", in.magic)
   }
   say("")

   ov := 0
   for _, s := range in.seg {
      if len(carveRuns(in.merged, s.rva, s.size)) != 1 {
         ov++
      }
   }
   say("spans intersecting heap-exec blocks: %d of %d", ov, len(in.seg))
   say("")

   heapDesc := make(map[uint32]imgDesc, len(in.heaps))
   for _, h := range in.heaps {
      heapDesc[h.va] = h
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
         if int(h.rva) <= rva && rva < int(h.rva+h.ln) {
            return d, h.rva, h.ln, true
         }
      }
      return 0, 0, 0, false
   }
   matchDesc := func(t int) (uint32, bool) {
      var best uint32
      bestDist := tol + 1
      for _, d := range descKeys {
         dist := max(int(d)-t, t-int(d))
         if dist < bestDist {
            best, bestDist = d, dist
         }
      }
      return best, bestDist <= tol
   }

   sites := bytes.Count(in.img, dpPattern)
   say("key-consumer size-check sites: %d at 0x%x", sites, bytes.Index(in.img, dpPattern))
   if sites != 1 {
      return fail("expected exactly one 'cmp dword ptr [rcx+0x14], 0x41' in the image")
   }

   dv0, c0, n0, ok := blockOf(bytes.Index(in.img, dpPattern))
   if !ok {
      return fail("no heap-exec block owns the size check")
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
                  t = o + 7 + int(int32(le32(in.img, o+3)))
               default:
                  continue
               }
            case in.img[o] == 0xE8 || in.img[o] == 0xE9:
               t = o + 5 + int(int32(le32(in.img, o+1)))
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
      return fail("no stage candidates - the lea/call idiom differs on this build")
   }

   exe, err := os.Executable()
   if err != nil {
      return fail("cannot locate own executable: %v", err)
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
      return fail("no candidate produced an OBF - stage 1 is not in the candidate set")
   }

   // The first OBF in descriptor order, not in string order: deterministic
   // without building and sorting a second slice for one element.
   obfFirst := ""
   for _, d1 := range descKeys {
      if v, ok := obfs[d1]; ok {
         obfFirst = v
         break
      }
   }

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

      obf := obfFirst
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
      return fail("no (stage 1, stage 2) pairing reproduced extracted.enc.pub")
   }

   plain, err := hex.DecodeString(found[5])
   if err != nil {
      return fail("bad plain hex from child: %v", err)
   }
   s1, err := strconv.ParseUint(found[0], 10, 32)
   if err != nil {
      return fail("bad stage-1 descriptor from child: %q", found[0])
   }
   s2, err := strconv.ParseUint(found[1], 10, 32)
   if err != nil {
      return fail("bad stage-2 descriptor from child: %q", found[1])
   }

   say("stage 1   0x%06x  (descriptor 0x%06x)", heapDesc[uint32(s1)].rva, s1)
   say("OBF       %s", found[2])
   say("stage 2   0x%06x  (descriptor 0x%06x)", heapDesc[uint32(s2)].rva, s2)
   say("in-mutated %s", found[3])
   say("mapped    %s", found[4])
   say("plain     %s", found[5])

   d := new(big.Int).SetBytes(plain)
   priv, err := ecdh.P256().NewPrivateKey(d.FillBytes(make([]byte, 32)))
   if err != nil {
      return fail("derived scalar out of range: %v", err)
   }
   if got := priv.PublicKey().Bytes()[1:]; !bytes.Equal(got, in.pub) {
      return fail("scalar does not reproduce %s\n  got  %x\n  want %x", encPubPath, got, in.pub)
   }

   say("pubkey    MATCH")
   if err := os.WriteFile(encPlainPath, plain, 0o644); err != nil {
      return fail("write %s: %v", encPlainPath, err)
   }
   psum := sha256.Sum256(plain)
   say("written   %s  (%d bytes)  sha256 %x", encPlainPath, len(plain), psum)
   return 0
}

func dpLastLine(s string) string {
   ls := strings.Split(strings.TrimRight(s, "\r\n"), "\n")
   return strings.TrimSpace(ls[len(ls)-1])
}

func dpTag(mode string) string {
   if mode == "s1" {
      return "S1"
   }
   return "S2"
}

// --- stage entry point ------------------------------------------------------

func stageDerivePlain(args []string) int {
   // Internal trial modes. Positional, so the command line surface stays at
   // exactly -1 through -7.
   if len(args) > 0 && (args[0] == "s1" || args[0] == "s2") {
      mode, a := args[0], args[1:]
      if len(a) < 1 {
         fmt.Fprintln(os.Stderr,
            "usage: prkf -7 s1 <desc> [prep] | prkf -7 s2 <desc> <obf> [prep] [variant]")
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
               "usage: prkf -7 s2 <desc> <obf> [prep] [variant]")
            return 2
         }
         obf = a[1]
         if len(a) > 2 {
            prep = a[2]
         }
         if len(a) > 3 {
            v, err := strconv.Atoi(a[3])
            if err != nil {
               fmt.Fprintf(os.Stderr, "prkf -7: bad variant %q: %v\n", a[3], err)
               return 2
            }
            variant = v
         }
      }
      return dpWorker(mode, uint32(d), obf, prep, variant)
   }
   if len(args) > 0 {
      fmt.Fprintf(os.Stderr, "prkf -7: unexpected argument %q\n", args[0])
      return 2
   }

   return dpDriver()
}

type dpInputs struct {
   img     []byte
   fb      []byte
   secs    []imgSection
   seg     []imgSpan
   heaps   []imgDesc
   merged  []imgInterval
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

   if in.img, err = os.ReadFile(imgPath); err != nil {
      return nil, err
   }

   // oracle_map.json, parsed here rather than in a single-caller helper: the
   // map, the cluster RVA and the magic sequence all land in dpInputs, and a
   // separate function would only hand back the same three values.
   raw, err := os.ReadFile(mapPath)
   if err != nil {
      return nil, err
   }
   var o dpOracle
   if err := json.Unmarshal(raw, &o); err != nil {
      return nil, err
   }
   if o.Map == nil {
      return nil, fmt.Errorf("%s is in the old flat format - re-run prkf -6", mapPath)
   }
   in.mapt = make(map[int]int, len(o.Map))
   for k, v := range o.Map {
      ki, err := strconv.Atoi(k)
      if err != nil {
         return nil, fmt.Errorf("%s: bad map key %q", mapPath, k)
      }
      in.mapt[ki] = v
   }
   in.cluster, in.magic = uint32(o.Cluster), o.Magic

   if in.prv, err = os.ReadFile(encPrvPath); err != nil {
      return nil, err
   }
   if len(in.prv) != 0x41 {
      return nil, fmt.Errorf("%s is %d bytes, expected 0x41 (65)", encPrvPath, len(in.prv))
   }
   pub, err := os.ReadFile(encPubPath)
   if err != nil {
      return nil, err
   }
   if len(pub) < 64 {
      return nil, fmt.Errorf("%s: need at least 64 bytes, got %d", encPubPath, len(pub))
   }
   in.pub = pub[len(pub)-64:]

   if in.fb, err = os.ReadFile(dllPath); err != nil {
      return nil, err
   }
   in.sizeImg, in.secs = peSections(in.fb)

   // -7 patches each range once, so unlike -5 it deduplicates by RVA. The
   // order of first appearance is kept, which is the order the descriptors
   // appear in the file.
   segs, heaps := splitDescs(in.fb, in.secs)
   in.heaps = heaps
   seen := map[uint32]bool{}
   for _, d := range segs {
      for _, sp := range segSpans(in.fb, d, in.sizeImg) {
         if seen[sp.rva] {
            continue
         }
         seen[sp.rva] = true
         in.seg = append(in.seg, sp)
      }
   }

   in.merged = mergeIntervals(heapIntervals(heaps))
   return in, nil
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

// dpRunChild spawns one trial as `exe -7 <mode> <args...>`. Positional, so no
// flag is ever involved.
func dpRunChild(exe, mode string, args ...string) dpResult {
   ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
   defer cancel()

   cmd := exec.CommandContext(ctx, exe, append([]string{"-7", mode}, args...)...)
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

// plainkey.go end
