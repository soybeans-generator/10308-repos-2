// stages.go begin
//go:build windows

// -6's search: walk the code graph outward from the key consumer, then try every
// ordered (stage 1, stage 2) pair until the sample's public key comes back.
//
//   stage 1  key half  --stage-1 routine-->  OBF
//   stage 2  OBF       --stage-2 routine-->  mut
//   stage 3  mut   --64 per-nibble bijection subtables-->  mapped
//   stage 4  mapped --16-entry permutation-->  plain
//
// # THE SEARCH LIVES UNDER -6
//
// It used to have a flag of its own, numbered before the carve step, and that could
// not work: every candidate is accepted or rejected by d*G == extracted.enc.pub, the
// only termination criterion, and there is no sample before -4. -6 always has one,
// so the search lives here, cached per family, and the two trial modes are its
// children rather than flags.
//
// key[0x40] % 3 selects one of three routine families, each with its own bijection
// table AND its own stage routines, so a pairing found with one family's sample
// says nothing about another's.
//
// # ONE CHILD PER CANDIDATE
//
// These are arbitrary code blobs called with arbitrary inputs, and some write
// outside the buffers they are handed. A child that tried forty combinations
// produced a match a single call could not reproduce, so every candidate gets its
// own process. A child is cheap because -2 caches the descriptor census: no DLL
// read, no scan, just the image and the patch.
//
// # THE SEARCH IS EXHAUSTIVE OVER WHAT CAN VARIATE
//
// Both stages share one candidate set and every ordered pair is tried. op=3 gets a
// 0x20-byte key and two 0x20-byte buffers, and which buffer a routine writes is not
// stated anywhere, so every trial reports both and the parent tries each. The
// winner is recorded - S1, S2, K1, O1, K2, O2 - and the apply path replays it.
//
// # THE WALK MATCHES BOTH ADDRESSES
//
// A lea/call target names either a descriptor's own address (what op=3 is handed)
// or its descVA (what the kernel executes, so what a call inside the image
// targets). Indexing only one of them misses the real stages whenever they differ.
//
// The caps bound the walk. On the recorded build the two stages sit inside the
// first seven hops, which reaches 22 candidates; exhausting the call graph reaches
// hundreds and buries them in noise. Hitting a cap is reported as TRUNCATED.
//
// USAGE  prkf -6 discovers, caches and applies. Its children are selected by
// trialEnv and take no arguments (see childMode in child.go):
//
//   p1;<desc>,...                      every descriptor as stage 1, both halves
//   p2;<start>;<obf>,...;<desc>,...    every pair as stage 2, both halves
package main

import (
   "bytes"
   "encoding/hex"
   "fmt"
   "os"
   "slices"
   "strconv"
   "strings"
   "time"
)

// dpPattern is the size-check signature: the consumer's own test, and the anchor
// both the walk here and -3's census of the consumer are built on.
var dpPattern = []byte{0x83, 0x79, 0x14, 0x41} // cmp dword ptr [rcx+0x14], 0x41

// dpDescList parses a list of descriptor addresses, each in any base. The child
// payloads are built from the same formatting, so this is also what validates them
// on the way back in.
func dpDescList(xs []string) ([]uint32, bool) {
   out := make([]uint32, 0, len(xs))
   for _, x := range xs {
      v, err := strconv.ParseUint(x, 0, 32)
      if err != nil {
         return nil, false
      }
      out = append(out, uint32(v))
   }
   return out, len(out) > 0
}

// --- stage entry point ------------------------------------------------------

// dpTrialChild dispatches the two trial modes. spec is the value of trialEnv,
// ';'-separated, and its stdout is parsed by the parent, so a malformed spec is
// exit code 2 with the shape on stderr.
func dpTrialChild(spec string) int {
   f := strings.Split(spec, ";")
   switch f[0] {
   case "p1":
      if len(f) != 2 {
         fmt.Fprintln(os.Stderr, "prkf: "+trialEnv+": want p1;<desc>,...")
         return 2
      }
      descs, ok := dpDescList(strings.Split(f[1], ","))
      if !ok {
         fmt.Fprintln(os.Stderr, "prkf: "+trialEnv+": bad descriptor list")
         return 2
      }
      return dpWorkerP1(descs)
   case "p2":
      if len(f) != 4 {
         fmt.Fprintln(os.Stderr, "prkf: "+trialEnv+": want p2;<start>;<obf>,...;<desc>,...")
         return 2
      }
      start, err := strconv.Atoi(f[1])
      if err != nil || start < 0 {
         fmt.Fprintf(os.Stderr, "prkf: "+trialEnv+": bad start %q\n", f[1])
         return 2
      }
      descs, ok := dpDescList(strings.Split(f[3], ","))
      if !ok {
         fmt.Fprintln(os.Stderr, "prkf: "+trialEnv+": bad descriptor list")
         return 2
      }
      return dpWorkerP2(start, strings.Split(f[2], ","), descs)
   }
   fmt.Fprintf(os.Stderr, "prkf: "+trialEnv+": unknown mode %q\n", f[0])
   return 2
}

// isZeroHex reports whether a hex field is absent or all zero bytes. A stage that
// writes nothing is not a stage: an all-zero buffer carries no information and would
// only add pairs to the matrix.
func isZeroHex(s string) bool {
   if len(s) != 0x40 {
      return true
   }
   for i := 0; i < len(s); i++ {
      if s[i] != '0' {
         return false
      }
   }
   return true
}

// dpFindStages is the search. It returns one confirmed pairing and writes nothing:
// the caller caches it. The public key to verify against arrives as an argument
// rather than being read here, so the function has one input it cannot get wrong.
func dpFindStages(in *dpInputs, fam int, want []byte, say func(string, ...any)) (*profileStages, error) {
   const (
      tol     = 0x20 // a lea/call target this close to a descriptor is that descriptor
      winSz   = 0x400
      maxHops = 7
      maxBlk  = 4000
   )

   ov := 0
   for _, s := range in.seg {
      if len(carveRuns(in.merged, s.rva, s.size)) != 1 {
         ov++
      }
   }
   say("spans intersecting heap-exec blocks: %d of %d", ov, len(in.seg))
   say("")

   blockOf := func(rva int) (imgDesc, bool) {
      for _, h := range in.heaps {
         if h.ln != 0 && int(h.rva) <= rva && rva < int(h.rva+h.ln) {
            return h, true
         }
      }
      return imgDesc{}, false
   }
   matchDesc := func(t int) (uint32, bool) {
      best, bestDist := uint32(0), tol+1
      for _, h := range in.heaps {
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

   say("heap-exec descriptors %d", len(in.heaps))
   if bytes.Count(in.img, dpPattern) != 1 {
      return nil, fmt.Errorf("expected exactly one 'cmp dword ptr [rcx+0x14], 0x41' in the image")
   }
   site := bytes.Index(in.img, dpPattern)
   owner, ok := blockOf(site)
   if !ok {
      return nil, fmt.Errorf("no heap-exec block owns the size check")
   }
   say("key consumer: descriptor 0x%06x  code 0x%06x+0x%x", owner.descVA, owner.rva, owner.ln)
   say("")

   // ---- walk the code graph outward from the key consumer ------------------
   cand := map[uint32]bool{}
   visited := map[[2]int]bool{}
   frontier := [][2]int{{int(owner.rva), int(owner.ln)}}
   depth, why := 0, ""

   for len(frontier) > 0 && depth < maxHops && len(visited) < maxBlk {
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
            if h, ok := blockOf(t); ok {
               nxt = append(nxt, [2]int{int(h.rva), int(h.ln)})
            } else if t >= 0x1000 && t < len(in.img)-0x40 {
               nxt = append(nxt, [2]int{t, min(winSz, len(in.img)-t)})
            }
         }
      }

      say("  hop %d: blocks %d -> descriptors %d, next %d",
         depth, len(frontier), len(cand), len(nxt))
      frontier = nxt
   }

   switch {
   case len(frontier) > 0 && depth >= maxHops:
      why = fmt.Sprintf("hop cap %d reached with %d blocks unexplored", maxHops, len(frontier))
   case len(frontier) > 0 && len(visited) >= maxBlk:
      why = fmt.Sprintf("block cap %d reached with %d blocks unexplored", maxBlk, len(frontier))
   }
   if why != "" {
      say("")
      say("TRUNCATED: %s", why)
      say("  the candidate set below is incomplete, so a miss is not evidence of")
      say("  absence. Raise the caps in dpFindStages and re-run.")
   }

   candList := make([]uint32, 0, len(cand))
   for d := range cand {
      candList = append(candList, d)
   }
   slices.Sort(candList)

   say("")
   say("stage candidates: %d descriptors, %d blocks visited in %d hops",
      len(candList), len(visited), depth)
   say("  %#x", candList)
   say("")
   if len(candList) == 0 {
      return nil, fmt.Errorf("no stage candidates - the lea/call idiom differs on this build")
   }

   // ---- phase 1: every candidate as stage 1, one child each ----------------
   // One child per candidate, because these are arbitrary code blobs: a routine
   // that writes outside its buffers would otherwise corrupt the image for every
   // candidate called after it in the same process.
   say("phase 1: %d candidates x 2 key halves, one child each", len(candList))

   var obfs []dpObf
   faulted := map[uint32]bool{}
   for _, d := range candList {
      b := dpRunP1([]uint32{d})
      if b.loadfail != "" {
         return nil, fmt.Errorf("%s", b.loadfail)
      }
      if len(b.res) == 0 {
         faulted[d] = true
         say("  0x%06x faults on its first call - skipped", d)
         continue
      }
      n := 0
      for _, r := range b.res {
         if r.kind != "RES" {
            continue
         }
         for o, v := range [2]string{r.a, r.b} {
            if isZeroHex(v) {
               continue
            }
            obfs = append(obfs, dpObf{d1: d, h: r.h, o: o, v: v})
            n++
         }
      }
      if n == 0 {
         say("  0x%06x REJECT for both halves", d)
      } else {
         say("  0x%06x %d output(s)", d, n)
      }
   }

   // Deduplicate by value: two candidates producing the same bytes are
   // indistinguishable downstream, and trying both doubles the work for nothing.
   var obfList []dpObf
   seenv := map[string]bool{}
   for _, o := range obfs {
      if seenv[o.v] {
         continue
      }
      seenv[o.v] = true
      obfList = append(obfList, o)
   }
   say("")
   say("distinct OBFs: %d", len(obfList))
   say("")
   if len(obfList) == 0 {
      return nil, fmt.Errorf("no candidate produced a non-zero output for either key half\n" +
         "  stage 1 is not in the candidate set, or it rejects this sample's key")
   }

   // ---- phase 2: every non-faulting candidate as stage 2, one child each ---
   var d2s []uint32
   for _, d := range candList {
      if !faulted[d] {
         d2s = append(d2s, d)
      }
   }
   say("phase 2: %d stage-2 candidates x %d OBFs x 2 key halves, one child each",
      len(d2s), len(obfList))
   say("")

   for _, d2 := range d2s {
      b := dpRunP2(0, obfList, []uint32{d2})
      if b.loadfail != "" {
         return nil, fmt.Errorf("%s", b.loadfail)
      }
      if len(b.res) == 0 {
         say("  0x%06x faults on its first input - skipped", d2)
         continue
      }

      nMut := 0
      var st *profileStages
      for _, m := range b.res {
         if m.kind != "RES" {
            continue
         }
         nMut++

         // m.a is the key buffer, m.b the output buffer; O2 selects between them.
         for o2, buf := range [2]string{m.a, m.b} {
            mut, err := hex.DecodeString(buf)
            if err != nil || len(mut) != 0x20 {
               continue
            }
            plain, ok := dpChain(in.img, in.cluster[fam], in.mapt[fam], mut)
            if !ok || !pubMatches(plain, want) {
               continue
            }
            o := obfList[m.i/2]
            st = &profileStages{
               S1: o.d1, K1: o.h, O1: o.o,
               S2: d2, K2: m.i % 2, O2: o2,
            }
            break
         }
         if st != nil {
            break
         }
      }

      if st == nil {
         say("  0x%06x %d mut - no match", d2, nMut)
         continue
      }

      // Confirm through the exact path -6 will use. A child can produce a match a
      // single call cannot reproduce - a sibling candidate may have corrupted the
      // image - and a pairing that cannot be applied is not a pairing.
      say("  0x%06x candidate match, confirming", d2)
      plain, err := dpApply(in, fam, st, say)
      if err != nil || !pubMatches(plain, want) {
         say("  not reproducible - continuing")
         say("")
         continue
      }
      say("")
      say("MATCH")
      say("  stage 1  0x%06x  key half %d  out buffer %d", st.S1, st.K1, st.O1)
      say("  stage 2  0x%06x  key half %d  out buffer %d", st.S2, st.K2, st.O2)
      return st, nil
   }

   say("")
   if why != "" {
      return nil, fmt.Errorf("no pairing found, but the walk was TRUNCATED - the search\n" +
         "  was not exhaustive, so this is not a conclusion. Raise the caps in dpFindStages")
   }
   say("no pairing reproduced %s.", encPubPath)
   say("  %d stage-1 candidates produced %d distinct OBF(s) over both key halves;",
      len(candList), len(obfList))
   say("  %d stage-2 candidates were tried against each, with both halves and both",
      len(d2s))
   say("  buffers, each in its own child. Nothing matched, so one of these is wrong:")
   say("    - stage 1 or stage 2 is outside the candidate set")
   say("    - stage 3/4 are not the consumer's table and permutation")
   say("    - %s does not hold this build's family %d table", profilePath, fam)
   return nil, fmt.Errorf("no (stage 1, stage 2) pairing reproduced %s", encPubPath)
}

// dpBatch is one trial child, parsed: its rows, or the reason it produced none.
type dpBatch struct {
   res      []dpRow
   loadfail string
}

// dpParse turns a trial child's stdout into rows. Both phases print the same shape:
//
//   RES <i> <half> <a> <b>      one 0x20-byte buffer per field, hex
//   RES <i> <half> REJECT rc=.. st=..
//
// Only lines carrying the phase prefix are read, which is also why a FAULT line -
// printed unprefixed, by the child's own handler - is not a row.
func dpParse(p procOut, pre string) dpBatch {
   var r dpBatch
   if p.err != nil {
      r.loadfail = "LOADFAIL " + p.err.Error()
      return r
   }
   for _, ln := range strings.Split(string(p.stdout), "\n") {
      x := strings.TrimSuffix(ln, "\r")
      if !strings.HasPrefix(x, pre) {
         continue
      }
      f := strings.Fields(x[len(pre):])
      if len(f) < 2 {
         continue
      }
      switch f[0] {
      case "LOADFAIL":
         r.loadfail = x
      case "RES":
         if len(f) < 4 {
            r.loadfail = "LOADFAIL malformed row: " + x
            return r
         }
         i, e1 := strconv.Atoi(f[1])
         h, e2 := strconv.Atoi(f[2])
         if e1 != nil || e2 != nil {
            r.loadfail = "LOADFAIL malformed row: " + x
            return r
         }
         if f[3] == "REJECT" {
            r.res = append(r.res, dpRow{i: i, h: h, kind: "REJECT"})
            continue
         }
         if len(f) < 5 {
            r.loadfail = "LOADFAIL malformed row: " + x
            return r
         }
         r.res = append(r.res, dpRow{i: i, h: h, kind: "RES", a: f[3], b: f[4]})
      }
   }
   return r
}

// dpRunP1 spawns one stage-1 probe child and parses its rows.
func dpRunP1(descs []uint32) dpBatch {
   ds := make([]string, len(descs))
   for i, d := range descs {
      ds[i] = fmt.Sprintf("0x%x", d)
   }
   return dpParse(runCollect(trialEnv+"=p1;"+strings.Join(ds, ","), 300*time.Second), "S1 ")
}

// dpRunP2 spawns one stage-2 probe child and parses its rows.
func dpRunP2(start int, obfs []dpObf, descs []uint32) dpBatch {
   os := make([]string, len(obfs))
   for i, o := range obfs {
      os[i] = o.v
   }
   ds := make([]string, len(descs))
   for i, d := range descs {
      ds[i] = fmt.Sprintf("0x%x", d)
   }
   spec := strings.Join([]string{
      "p2", strconv.Itoa(start),
      strings.Join(os, ","), strings.Join(ds, ","),
   }, ";")
   return dpParse(runCollect(trialEnv+"="+spec, 300*time.Second), "MX ")
}

// dpObf is one stage-1 output: the candidate, key half and buffer that produced it,
// and the 0x20-byte value.
type dpObf struct {
   d1 uint32
   h  int // key half stage 1 was given
   o  int // buffer index the value was read from
   v  string
}

// dpRow is one row from a trial child. a and b are the two 0x20-byte buffers in
// call order: for a stage-1 row that is out then key, for a stage-2 row key then
// out.
type dpRow struct {
   i    int
   h    int
   kind string // RES or REJECT
   a    string
   b    string
}

// stages.go end
