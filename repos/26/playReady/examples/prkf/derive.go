// derive.go begin
//go:build windows

// prkf -6: derive the encryption key. Discover the (stage 1, stage 2) pairing for the
// sample's family if the profile does not already hold one, replay it, and write the key.
//
//   stage 1  key half  --stage-1 routine-->  OBF
//   stage 2  OBF       --stage-2 routine-->  mut
//   stage 3  mut   --64 per-nibble bijection subtables-->  mapped
//   stage 4  mapped --16-entry permutation-->  plain
//
//   Proven by d*G == extracted.enc.pub. Nothing is written unless it holds.
//
// The search below walks the code graph outward from the key consumer and tries every ordered
// pair; the apply path replays the recorded pairing through the same two children. They are
// together because a pairing is only a pairing when it can be applied: the search confirms
// every candidate match through dpApply before returning it.
//
// ONE CHILD PER CANDIDATE: these are arbitrary code blobs called with arbitrary inputs, and
// some write outside the buffers they are handed. A child that tried forty combinations
// produced a match a single call could not reproduce. A child is cheap because -2 caches the
// descriptor census: no DLL read, no scan, just the image and the patch.
//
// THE SEARCH IS EXHAUSTIVE OVER WHAT CAN VARIATE. Both stages share one candidate set and
// every ordered pair is tried. op=3 gets a 0x20-byte key and two 0x20-byte buffers, and which
// buffer a routine writes is not stated anywhere, so every trial reports both and the parent
// tries each. The winner is recorded - S1, S2, K1, O1, K2, O2 - and the apply path replays it.
//
// THE WALK MATCHES BOTH ADDRESSES: a lea/call target names either a descriptor's own address
// or its descVA. Indexing only one of them misses the real stages whenever they differ. The
// caps bound the walk; hitting one is reported as TRUNCATED, and a miss under a TRUNCATED walk
// is not evidence of absence.
//
// STAGES 3 AND 4 ARE ONE PASS: mut is 32 bytes, so 64 nibbles. Nibble i selects one byte from
// its own 16-byte row at the family's cluster, and that byte indexes the 16-entry permutation.
//
// key[0x40] % 3 selects one of three routine families, each with its own bijection table AND
// its own stage routines, so a search records only the family it was run for.
package main

import (
   "bytes"
   "crypto/sha256"
   "encoding/hex"
   "fmt"
   "os"
   "slices"
   "strconv"
   "strings"
   "time"
)

// dpPattern is the size-check signature: the consumer's own test, and the anchor both the walk
// here and -3's census of the consumer are built on.
var dpPattern = []byte{0x83, 0x79, 0x14, 0x41} // cmp dword ptr [rcx+0x14], 0x41

// ---------------------------------------------------------------- the apply

// dpApply replays a pairing and returns the scalar its chain produces. Two children - p1 for
// stage 1, p2 for stage 2 - because those are the only trial modes there are. Stages 3 and 4
// are pure table work, so they run here.
func dpApply(in *dpInputs, fam int, st *profileStages, say func(string, ...any)) ([]byte, error) {
   t := in.tab[fam]
   if t == nil {
      return nil, fmt.Errorf("no family %d table in %s - re-run prkf -3", fam, profilePath)
   }
   say("family %d  cluster 0x%06x", fam, t.cluster)
   say("stage 1  0x%06x  key half %d  out buffer %d", st.S1, st.K1, st.O1)
   say("stage 2  0x%06x  key half %d  out buffer %d", st.S2, st.K2, st.O2)
   say("")

   // Every index in a recorded pairing comes out of dllprof.json. O1/O2 index a two-element
   // array, so an out-of-range value would panic; K1/K2 would only match no row and the
   // failure would read as "produced no output".
   if !is01(st.K1) || !is01(st.O1) || !is01(st.K2) || !is01(st.O2) {
      return nil, fmt.Errorf("recorded pairing %+v has an index outside 0..1 - %s is corrupt",
         *st, profilePath)
   }

   // p1 runs both halves and prints both buffers, so the recorded half and buffer are picked
   // out of the two rows rather than requested.
   b1 := dpRunP1([]uint32{st.S1})
   if b1.err != nil {
      return nil, b1.err
   }
   var obf []byte
   for _, r := range b1.res {
      if r.Kind != "ok" || r.Half != st.K1 {
         continue
      }
      v, err := hex.DecodeString(r.Buf[st.O1])
      if err != nil {
         return nil, fmt.Errorf("stage 1 (0x%06x): key half %d buffer %d: %w",
            st.S1, st.K1, st.O1, err)
      }
      obf = v
   }
   if len(obf) != 0x20 {
      return nil, fmt.Errorf("stage 1 (0x%06x) produced no output for key half %d\n"+
         "  the pairing does not apply to this build", st.S1, st.K1)
   }
   say("  obf       %x", obf)

   b2 := dpRunP2(0, []dpObf{{v: hex.EncodeToString(obf)}}, []uint32{st.S2})
   if b2.err != nil {
      return nil, b2.err
   }
   var mut []byte
   for _, r := range b2.res {
      if r.Kind != "ok" || r.Half != st.K2 {
         continue
      }
      v, err := hex.DecodeString(r.Buf[st.O2])
      if err != nil {
         return nil, fmt.Errorf("stage 2 (0x%06x): key half %d buffer %d: %w",
            st.S2, st.K2, st.O2, err)
      }
      mut = v
   }
   if len(mut) != 0x20 {
      return nil, fmt.Errorf("stage 2 (0x%06x) produced no output for key half %d\n"+
         "  the pairing does not apply to this build", st.S2, st.K2)
   }
   say("  mut       %x", mut)

   plain, ok := dpChain(in.img, t, mut)
   if !ok {
      return nil, fmt.Errorf("stages 3 and 4 could not be applied - re-run prkf -3")
   }
   say("  plain     %x", plain)
   return plain, nil
}

// dpChain applies stages 3 and 4 in one pass.
//
// mut is 32 bytes, so 64 nibbles, high nibble first. Nibble i selects one byte from its own
// 16-byte row at the family's cluster - a value in 0..15 - and that value indexes the
// 16-entry permutation. The packed form is rebuilt at the end.
//
// An image byte above 0x0F means the cluster is not the table the profile says it is, which is
// a wrong profile rather than a wrong scalar, so it fails instead of masking.
func dpChain(img []byte, t *famTab, mut []byte) ([]byte, bool) {
   if len(mut) < 0x20 {
      return nil, false
   }
   c := int(t.cluster)
   if c < 0 || c+64*16 > len(img) {
      return nil, false
   }

   var pl [64]byte
   for i := range pl {
      nib := mut[i>>1] >> (4 - uint(i%2)*4) & 0xF // high nibble first
      b := img[c+i*16+int(nib)]
      if b > 15 {
         return nil, false
      }
      pl[i] = byte(t.perm[b])
   }

   // 32 bytes out of 64 nibbles: a fixed size, so an array and a slice of it.
   var out [32]byte
   for i := 0; i < 64; i += 2 {
      out[i/2] = pl[i]<<4 | pl[i+1]
   }
   return out[:], true
}

// dpCommit is the one place a derived scalar becomes a file. The check is repeated here rather
// than trusted from the caller: this is the only write, so it is the only place a wrong scalar
// could reach the disk.
func dpCommit(plain, want []byte, say func(string, ...any)) error {
   if !pubMatches(plain, want) {
      return fmt.Errorf("scalar does not reproduce %s\n  got  %x\n  want %x",
         encPubPath, pubFor(plain), pubBytes(want))
   }
   say("pubkey    MATCH")
   if err := os.WriteFile(encPlainPath, plain, 0o644); err != nil {
      return fmt.Errorf("write %s: %v", encPlainPath, err)
   }
   psum := sha256.Sum256(plain)
   say("written   %s  (%d bytes)  sha256 %x", encPlainPath, len(plain), psum)
   return nil
}

// dpDerive is -6: discover if needed, replay, write.
func dpDerive() (code int) {
   lg := newStepLog(plainLogPath)
   defer lg.Finish(&code)
   say, fail := lg.Printf, lg.Failf

   in, err := dpLoadInputs()
   if err != nil {
      return fail("%v", err)
   }

   // The pairing is found by running a real key through the stages and verified by
   // d*G == extracted.enc.pub; a synthetic key cannot be used because the routines reject it.
   prv, pub, err := dpSample()
   if err != nil {
      return fail("%v", err)
   }
   fam := int(prv[0x40]) % 3
   if _, ok := in.tab[fam]; !ok {
      return fail("%s selects routine family %d, but %s holds only %v\n"+
         "  that family produced no live set on this build: re-run prkf -3",
         encPrvPath, fam, profilePath, in.fams)
   }

   say("dll    %s", in.sha)
   say("image  %s  (%d bytes, SizeOfImage 0x%x)", imgPath, len(in.img), in.size)
   say("prv    %s  family %d (key[0x40]=0x%02x %%3)", encPrvPath, fam, prv[0x40])
   say("pub    %s", encPubPath)
   say("")

   st := in.prof.Stages[vkey(fam)]
   if st == nil {
      // A family this build has no pairing for. Discover it with this sample, then cache it,
      // so every later sample of this family is instant.
      say("no stage pairing for family %d - discovering it with this sample", fam)
      say("")
      if st, err = dpFindStages(in, fam, pub, say); err != nil {
         return fail("%v", err)
      }
      // Assigned, not replaced: the stage routines are selected by the same byte as the
      // bijection table, so this search says nothing about another family.
      if in.prof.Stages == nil {
         in.prof.Stages = map[string]*profileStages{}
      }
      in.prof.Stages[vkey(fam)] = st
      if err := pfSave(in.prof); err != nil {
         return fail("write %s: %v", profilePath, err)
      }
      say("")
      say("cached s1=0x%06x s2=0x%06x for family %d in %s", st.S1, st.S2, fam, profilePath)
      say("")
   }

   plain, err := dpApply(in, fam, st, say)
   if err != nil {
      return fail("%v", err)
   }
   if err := dpCommit(plain, pub, say); err != nil {
      return fail("%v", err)
   }
   return 0
}

// dpSample returns the sample's 0x41-byte key component and its P-256 public key, carving them
// out of the BLA when -4 has not written them yet.
func dpSample() (prv, pub []byte, err error) {
   if !isFile(encPrvPath) || !isFile(encPubPath) {
      fmt.Printf("carving the key components from %s\n\n", corePath)
      if err := cmdExtract(); err != nil {
         return nil, nil, fmt.Errorf("cannot carve %s: %w", corePath, err)
      }
      fmt.Println()
   }

   if prv, err = os.ReadFile(encPrvPath); err != nil {
      return nil, nil, err
   }
   if len(prv) != 0x41 {
      return nil, nil, fmt.Errorf("%s is %d bytes, expected 0x41 (65)", encPrvPath, len(prv))
   }
   if pub, err = os.ReadFile(encPubPath); err != nil {
      return nil, nil, err
   }
   if len(pub) < 64 {
      return nil, nil, fmt.Errorf("%s: need at least 64 bytes, got %d", encPubPath, len(pub))
   }
   return prv, pub[len(pub)-64:], nil
}

// is01 reports whether a recorded half/buffer index is one of the two values a trial row can
// carry.
func is01(v int) bool { return v == 0 || v == 1 }

// isZeroHex reports whether a hex field is absent or all zero bytes. A stage that writes
// nothing is not a stage: an all-zero buffer carries no information and would only add pairs to
// the matrix.
//
// The 0x40-length test is what rejects an absent field, and it is not redundant with the trim:
// a 64-character string of any other hex digits trims to itself.
func isZeroHex(s string) bool {
   return len(s) != 0x40 || strings.Trim(s, "0") == ""
}

// ---------------------------------------------------------------- the search

// dpFindStages is the search. It returns one confirmed pairing and writes nothing: the caller
// caches it. The public key to verify against arrives as an argument rather than being read
// here, so the function has one input it cannot get wrong.
func dpFindStages(in *dpInputs, fam int, want []byte, say func(string, ...any)) (*profileStages, error) {
   const (
      tol     = 0x20 // a lea/call target this close to a descriptor is that descriptor
      winSz   = 0x400
      maxHops = 7
      maxBlk  = 4000
   )

   // &h is safe from Go 1.22 on: the loop variable is per-iteration, so the return cannot
   // alias a later iteration.
   blockOf := func(rva int) (*imgDesc, bool) {
      for _, h := range in.heaps {
         if h.ln != 0 && int(h.rva) <= rva && rva < int(h.rva+h.ln) {
            return &h, true
         }
      }
      return nil, false
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
   say("phase 1: %d candidates x 2 key halves, one child each", len(candList))

   var obfs []dpObf
   faulted := map[uint32]bool{}
   for _, d := range candList {
      b := dpRunP1([]uint32{d})
      if b.err != nil {
         return nil, b.err
      }
      if len(b.res) == 0 {
         faulted[d] = true
         say("  0x%06x faults on its first call - skipped", d)
         continue
      }
      n := 0
      for _, r := range b.res {
         if r.Kind != "ok" {
            continue
         }
         for o, v := range r.Buf {
            if isZeroHex(v) {
               continue
            }
            obfs = append(obfs, dpObf{d1: d, h: r.Half, o: o, v: v})
            n++
         }
      }
      if n == 0 {
         say("  0x%06x REJECT for both halves", d)
      } else {
         say("  0x%06x %d output(s)", d, n)
      }
   }

   // Deduplicate by value: two candidates producing the same bytes are indistinguishable
   // downstream.
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
      if b.err != nil {
         return nil, b.err
      }
      if len(b.res) == 0 {
         say("  0x%06x faults on its first input - skipped", d2)
         continue
      }

      nMut := 0
      var st *profileStages
      for _, m := range b.res {
         if m.Kind != "ok" {
            continue
         }
         nMut++

         // buf[0] is the key buffer, buf[1] the output buffer; O2 selects.
         for o2, buf := range m.Buf {
            mut, err := hex.DecodeString(buf)
            if err != nil || len(mut) != 0x20 {
               continue
            }
            plain, ok := dpChain(in.img, in.tab[fam], mut)
            if !ok || !pubMatches(plain, want) {
               continue
            }
            o := obfList[m.Idx]
            st = &profileStages{
               S1: o.d1, K1: o.h, O1: o.o,
               S2: d2, K2: m.Half, O2: o2,
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

      // Confirm through the exact path -6 will use: a child can produce a match a single call
      // cannot reproduce, and a pairing that cannot be applied is not a pairing.
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

   if why != "" {
      return nil, fmt.Errorf("no pairing found, but the walk was TRUNCATED - the search\n"+
         "  was not exhaustive, so this is not a conclusion. Raise the caps in dpFindStages\n"+
         "  (%s)", why)
   }
   return nil, fmt.Errorf("no (stage 1, stage 2) pairing reproduced %s\n"+
      "  %d stage-1 candidates produced %d distinct OBF(s); %d stage-2 candidates were\n"+
      "  tried against each, with both halves and both buffers, each in its own child.\n"+
      "  Nothing matched, so one of these is wrong:\n"+
      "    - stage 1 or stage 2 is outside the candidate set\n"+
      "    - stage 3/4 are not the consumer's table and permutation\n"+
      "    - %s does not hold this build's family %d table",
      encPubPath, len(candList), len(obfList), len(d2s), profilePath, fam)
}

// dpBatch is one trial child, parsed: its result rows, plus why it is unusable.
type dpBatch struct {
   res []childRow
   err error
}

// dpParse keeps only the rows a verdict can be read from. An err row means the child never got
// to try the candidate, which is a spawn or setup fault and not a property of the code under
// test, so it aborts the batch instead of skipping one entry.
func dpParse(p *procOut) *dpBatch {
   b := &dpBatch{}
   if p.err != nil {
      b.err = p.err
      return b
   }
   rows, err := readRows(p.stdout)
   if err != nil {
      b.err = err
      return b
   }
   for _, r := range rows {
      switch r.Kind {
      case "ok":
         if len(r.Buf) != 2 {
            b.err = fmt.Errorf("ok row with %d buffers, expected 2", len(r.Buf))
            return b
         }
         b.res = append(b.res, r)
      case "reject":
         b.res = append(b.res, r)
      case "err", "loadfail":
         b.err = fmt.Errorf("%s", r.Msg)
      }
   }
   return b
}

// dpRunP1 spawns one stage-1 probe child and parses its rows. Phase 1 is phase 2 with a single
// empty OBF, which selects the phase-1 argument shape.
func dpRunP1(descs []uint32) *dpBatch {
   return dpParse(runCollect(&childSpec{
      Mode:  "p1",
      Descs: descs,
      Obfs:  []string{""},
   }, 300*time.Second, nil))
}

// dpRunP2 spawns one stage-2 probe child and parses its rows.
func dpRunP2(start int, obfs []dpObf, descs []uint32) *dpBatch {
   vals := make([]string, len(obfs))
   for i, o := range obfs {
      vals[i] = o.v
   }
   return dpParse(runCollect(&childSpec{
      Mode:  "p2",
      Start: start,
      Obfs:  vals,
      Descs: descs,
   }, 300*time.Second, nil))
}

// dpInputs is the profile plus the family tables -6 needs. The image, census, patch plan and
// parsed profile all come from pfImage, which is the same load a trial child does.
type dpInputs struct {
   *pfImage
   fams []int
   tab  map[int]*famTab
}

// dpLoadInputs validates the profile pfPrep already parsed and builds the per-family tables.
// It does NOT read dllprof.json a second time, and does NOT call scanDescs.
func dpLoadInputs() (*dpInputs, error) {
   pi, err := pfPrep()
   if err != nil {
      return nil, err
   }
   if err := pfValidate(pi.prof, pi.sha); err != nil {
      return nil, err
   }

   in := &dpInputs{pfImage: pi, tab: make(map[int]*famTab, len(pi.prof.Map))}
   // pfValidate has already rejected any map key that is not a family index and any table
   // that is not a permutation, so neither Atoi nor the map can fail here. The Atoi error is
   // still returned: the alternative is a silent map[0] that hides the two disagreeing.
   for k, pm := range pi.prof.Map {
      v, err := strconv.Atoi(k)
      if err != nil {
         return nil, fmt.Errorf("%s: map key %q is not a family index: %w", profilePath, k, err)
      }
      in.tab[v] = &famTab{cluster: pm.Cluster, perm: pm.Map}
      in.fams = append(in.fams, v)
   }
   slices.Sort(in.fams)
   return in, nil
}

// dpObf is one stage-1 output: the candidate, key half and buffer that produced it, and the
// 0x20-byte value.
type dpObf struct {
   d1 uint32
   h  int // key half stage 1 was given
   o  int // buffer index the value was read from
   v  string
}

// famTab is one family's stage 3/4 tables. The cluster and the permutation travel together
// because stage 4 needs both and a profile can only be valid when both came from the same
// family.
type famTab struct {
   cluster uint32
   perm    [16]int // mapped nibble -> real nibble
}

// derive.go end
