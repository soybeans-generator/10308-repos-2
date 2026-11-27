// derive.go begin
// -6 and -7 on top of the emulator.
//
// The chain, the key checks and the stage search are pure computation; the only thing that
// needs the module is a call, and emu.go supplies that from wbtool_img.bin plus the memory
// prkf -4 captured. So these two steps run wherever Go runs, and they never open the DLL.
//
// THE CAPTURE IS OPTIONAL AND LOADED WHEN PRESENT. Without it, stage 1 reads pointer fields
// that are zero in the image and returns a wrong OBF, so -7 needs it; -6 does not, because the
// signing-key routine touches no such table.
package main

import (
   "bytes"
   "crypto/sha256"
   "encoding/hex"
   "encoding/json"
   "fmt"
   "os"
   "slices"
   "strconv"
)

// applyPairing replays a recorded pairing and returns the scalar its chain produces.
func applyPairing(im *image, fam int, st *profileStages,
   say func(string, ...any)) ([]byte, error) {

   tab, ok := im.famTab(fam)
   if !ok {
      return nil, fmt.Errorf("no family %d table in %s - re-run prkf -3", fam, profilePath)
   }
   say("family %d  cluster 0x%06x", fam, tab.cluster)
   say("stage 1  0x%06x  key half %d  out buffer %d", st.S1, st.K1, st.O1)
   say("stage 2  0x%06x  key half %d  out buffer %d", st.S2, st.K2, st.O2)
   say("")

   // Every index in a recorded pairing comes out of dllprof.json. O1/O2 index a two-element
   // array, so an out-of-range value would panic; K1/K2 would only match no row.
   if !is01(st.K1) || !is01(st.O1) || !is01(st.K2) || !is01(st.O2) {
      return nil, fmt.Errorf("recorded pairing %+v has an index outside 0..1 - %s is corrupt",
         *st, profilePath)
   }

   prv, err := dpSampleKey()
   if err != nil {
      return nil, err
   }

   res1, err := im.emu.call(st.S1, keyLen, dpHalf(prv, st.K1), make([]byte, keyLen), nil)
   if err != nil {
      return nil, err
   }
   if !zero4(res1.status) {
      return nil, fmt.Errorf("stage 1 (0x%06x) returned %s", st.S1, hex.EncodeToString(res1.status))
   }
   obf := pick(res1.key, res1.out, st.O1)[:keyLen]
   if isZeroHex(obf) {
      return nil, fmt.Errorf("stage 1 (0x%06x) produced no output for key half %d\n"+
         "  the pairing does not apply to this build", st.S1, st.K1)
   }
   say("  obf       %s", hex.EncodeToString(obf))

   res2, err := im.emu.call(st.S2, keyLen, obf, dpHalf(prv, st.K2), u32p(keyLen))
   if err != nil {
      return nil, err
   }
   if !zero4(res2.status) {
      return nil, fmt.Errorf("stage 2 (0x%06x) returned %s", st.S2, hex.EncodeToString(res2.status))
   }
   mut := pick(res2.key, res2.out, st.O2)[:keyLen]
   if isZeroHex(mut) {
      return nil, fmt.Errorf("stage 2 (0x%06x) produced no output for key half %d\n"+
         "  the pairing does not apply to this build", st.S2, st.K2)
   }
   say("  mut       %s", hex.EncodeToString(mut))

   plain, ok := dpChain(im.img, tab, mut)
   if !ok {
      return nil, fmt.Errorf("stages 3 and 4 could not be applied - re-run prkf -3")
   }
   say("  plain     %s", hex.EncodeToString(plain))
   return plain, nil
}

// ---------------------------------------------------------------- -6

// cmdDecrypt is -6: run the signing-key routine on the encrypted component, then prove the
// answer against the public key. The proof is the whole validation - nothing about the
// emulator is trusted.
func cmdDecrypt() error {
   if !isFile(sigPrvPath) {
      return fmt.Errorf("missing input: %s\n  run prkf -5 first", sigPrvPath)
   }
   if !isFile(sigPubPath) {
      return fmt.Errorf("missing public key: %s\n  run prkf -5 first", sigPubPath)
   }

   rec, err := loadPrsubs()
   if err != nil {
      return err
   }
   im, err := loadImage()
   if err != nil {
      return err
   }
   if rec.SHA256 != im.prof.DLLSHA256 {
      return fmt.Errorf("%s and %s were built for different DLLs\n  cache  : %s\n  profile: %s",
         prsubsPath, profilePath, rec.SHA256, im.prof.DLLSHA256)
   }

   enc, err := os.ReadFile(sigPrvPath)
   if err != nil {
      return err
   }
   if len(enc) != keyLen {
      return fmt.Errorf("%s: expected %d bytes, got %d", sigPrvPath, keyLen, len(enc))
   }

   res, err := im.emu.call(rec.DescVA, keyLen, enc, make([]byte, keyLen), nil)
   if err != nil {
      return err
   }
   if !zero4(res.status) {
      return fmt.Errorf("routine returned %s - the argument layout no longer matches "+
         "this build; re-run prkf -1", hex.EncodeToString(res.status))
   }
   plain := res.out[:keyLen]

   raw, err := os.ReadFile(sigPubPath)
   if err != nil {
      return err
   }
   if !pubMatches(plain, raw) {
      return fmt.Errorf("d*G != %s - the plaintext is not the private key for\n"+
         "that public key; the descriptor, the argument layout or the\n"+
         "input file is wrong; nothing was written", sigPubPath)
   }
   fmt.Printf("%s (%d bytes)\n", sigPrvPath, len(enc))
   fmt.Printf("plaintext %s\n", hex.EncodeToString(plain))
   want := pubBytes(raw)
   fmt.Printf("[ OK ] d*G == %s\n", sigPubPath)
   fmt.Printf("       Q = (%s,\n            %s)\n",
      hex.EncodeToString(want[1:33]), hex.EncodeToString(want[33:65]))

   if err := os.WriteFile(sigPlainPath, plain, 0o644); err != nil {
      return err
   }
   fmt.Printf("\nwrote %s (%d bytes)\n", sigPlainPath, len(plain))
   return nil
}

// ---------------------------------------------------------------- -7

// cmdDerive is -7: discover the pairing if the profile has none, replay it, write the key.
func cmdDerive() (code int) {
   lg := newStepLog(plainLogPath)
   defer lg.Finish(&code)
   say, fail := lg.Printf, lg.Failf

   im, err := loadImage()
   if err != nil {
      return fail("%v", err)
   }

   // A pairing is found by running a real key through the stages and verified by
   // d*G == extracted.enc.pub; a synthetic key cannot be used because the routines reject it.
   prv, pub, err := dpSample()
   if err != nil {
      return fail("%v", err)
   }
   fam := int(prv[0x40]) % 3
   if _, ok := im.famTab(fam); !ok {
      var fams []int
      for k := range im.prof.Map {
         if v, err := strconv.Atoi(k); err == nil {
            fams = append(fams, v)
         }
      }
      slices.Sort(fams)
      return fail("%s selects routine family %d, but %s holds only %v\n"+
         "  that family produced no live set on this build: re-run prkf -3",
         encPrvPath, fam, profilePath, fams)
   }

   say("dll    %s", im.prof.DLLSHA256)
   say("image  %s  (%d bytes, SizeOfImage 0x%x)", imgPath, len(im.img), im.prof.SizeOfImage)
   if im.captured {
      say("memory %s  base 0x%x  %d regions", memPath, im.base, len(im.emu.regions))
   } else {
      say("memory no capture - stage 1 will read zeroed globals")
   }
   say("prv    %s  family %d (key[0x40]=0x%02x %%3)", encPrvPath, fam, prv[0x40])
   say("pub    %s", encPubPath)
   say("")

   st := im.prof.Stages[vkey(fam)]
   if st == nil {
      say("no stage pairing for family %d - discovering it with this sample", fam)
      say("")
      if st, err = findStages(im, fam, pub, say); err != nil {
         return fail("%v", err)
      }
      if im.prof.Stages == nil {
         im.prof.Stages = map[string]*profileStages{}
      }
      im.prof.Stages[vkey(fam)] = st
      if err := saveProfile(im.prof); err != nil {
         return fail("write %s: %v", profilePath, err)
      }
      say("")
      say("cached s1=0x%06x s2=0x%06x for family %d in %s", st.S1, st.S2, fam, profilePath)
      say("")
   }

   plain, err := applyPairing(im, fam, st, say)
   if err != nil {
      return fail("%v", err)
   }
   if !pubMatches(plain, pub) {
      return fail("scalar does not reproduce %s\n  got  %s\n  want %s",
         encPubPath, hex.EncodeToString(pubFor(plain)), hex.EncodeToString(pubBytes(pub)))
   }
   say("pubkey    MATCH")
   if err := os.WriteFile(encPlainPath, plain, 0o644); err != nil {
      return fail("write %s: %v", encPlainPath, err)
   }
   psum := sha256.Sum256(plain)
   say("written   %s  (%d bytes)  sha256 %x", encPlainPath, len(plain), psum)
   return 0
}

// dpChain applies stages 3 and 4 in one pass: mut is 32 bytes, so 64 nibbles, high nibble
// first. Nibble i selects one byte from its own 16-byte row at the family's cluster, and that
// byte indexes the 16-entry permutation.
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
      nib := mut[i>>1] >> (4 - uint(i%2)*4) & 0xF
      b := img[c+i*16+int(nib)]
      if b > 15 {
         return nil, false
      }
      pl[i] = byte(t.perm[b])
   }
   out := make([]byte, 32)
   for i := 0; i < 64; i += 2 {
      out[i/2] = pl[i]<<4 | pl[i+1]
   }
   return out, true
}

func dpHalf(prv []byte, h int) []byte {
   if h == 1 {
      return prv[0x20:0x40]
   }
   return prv[0:0x20]
}

// dpSample returns the sample's 0x41-byte key component and its P-256 public key, carving them
// out of the BLA when -5 has not written them yet.
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

func dpSampleKey() ([]byte, error) {
   prv, err := os.ReadFile(encPrvPath)
   if err != nil {
      return nil, err
   }
   if len(prv) != 0x41 {
      return nil, fmt.Errorf("%s is %d bytes, expected 0x41 (65)", encPrvPath, len(prv))
   }
   return prv, nil
}

// ---------------------------------------------------------------- helpers

func is01(v int) bool { return v == 0 || v == 1 }

func isZeroHex(b []byte) bool {
   for _, c := range b {
      if c != 0 {
         return false
      }
   }
   return true
}

func pick(a, b []byte, i int) []byte {
   if i == 1 {
      return b
   }
   return a
}

func saveProfile(p *dllProfile) error {
   blob, err := json.MarshalIndent(p, "", "  ")
   if err != nil {
      return err
   }
   return os.WriteFile(profilePath, append(blob, '\n'), 0o644)
}

func u32p(v int) *uint32 {
   u := uint32(v)
   return &u
}

func zero4(b []byte) bool { return len(b) == 4 && b[0]|b[1]|b[2]|b[3] == 0 }

// ---------------------------------------------------------------- prsubs

// loadPrsubs reads prsubs.json. It does NOT open the DLL: the digest it carries is compared
// against the profile's, which -2 recorded.
func loadPrsubs() (*subRecord, error) {
   raw, err := os.ReadFile(prsubsPath)
   if err != nil {
      return nil, fmt.Errorf("no %s - run prkf -1", prsubsPath)
   }
   var rec subRecord
   if err := json.Unmarshal(raw, &rec); err != nil {
      return nil, fmt.Errorf("%s: %v", prsubsPath, err)
   }
   if rec.DescVA == 0 {
      return nil, fmt.Errorf("%s has no desc_va - re-run prkf -1", prsubsPath)
   }
   return &rec, nil
}

// ---------------------------------------------------------------- the search

// findStages walks the code graph outward from the key consumer, tries every ordered pair, and
// confirms a match through the exact path the next run will use.
//
// AN OBF IS 0x20 BYTES AND THE BUFFER IS 0x40. Both buffers come back whole from a call, so the
// value is truncated where it is recorded; without that every OBF decodes to 0x40, the phase-2
// length check rejects all of them, and each candidate reports "0 mut" - which reads like a
// refusal and is not one.
func findStages(im *image, fam int, want []byte, say func(string, ...any)) (*profileStages, error) {
   const (
      tol     = 0x20 // a lea/call target this close to a descriptor is that descriptor
      winSz   = 0x400
      maxHops = 10
      maxBlk  = 20000
   )

   blockOf := func(rva int) (*imgDesc, bool) {
      for i := range im.heaps {
         h := &im.heaps[i]
         if h.ln != 0 && int(h.rva) <= rva && rva < int(h.rva+h.ln) {
            return h, true
         }
      }
      return nil, false
   }
   matchDesc := func(t int) (uint32, bool) {
      best, bestDist := uint32(0), tol+1
      for _, h := range im.heaps {
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

   say("heap-exec descriptors %d", len(im.heaps))
   if bytes.Count(im.img, dpPattern) != 1 {
      return nil, fmt.Errorf("expected exactly one 'cmp dword ptr [rcx+0x14], 0x41' in the image")
   }
   site := bytes.Index(im.img, dpPattern)
   owner, ok := blockOf(site)
   if !ok {
      return nil, fmt.Errorf("no heap-exec block owns the size check")
   }
   say("key consumer: descriptor 0x%06x  code 0x%06x+0x%x", owner.descVA, owner.rva, owner.ln)
   say("")

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

         hi := min(b[0]+b[1], len(im.img)-8)
         for o := max(0x1000, b[0]); o < hi; o++ {
            var t int
            switch {
            case (im.img[o] == 0x48 || im.img[o] == 0x4C) && im.img[o+1] == 0x8D:
               switch im.img[o+2] {
               case 5, 0xD, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D:
                  t = o + 7 + int(int32(le32(im.img, o+3)))
               default:
                  continue
               }
            case im.img[o] == 0xE8 || im.img[o] == 0xE9:
               t = o + 5 + int(int32(le32(im.img, o+1)))
            default:
               continue
            }
            if m, ok := matchDesc(t); ok {
               cand[m] = true
               continue
            }
            if h, ok := blockOf(t); ok {
               nxt = append(nxt, [2]int{int(h.rva), int(h.ln)})
            } else if t >= 0x1000 && t < len(im.img)-0x40 {
               nxt = append(nxt, [2]int{t, min(winSz, len(im.img)-t)})
            }
         }
      }

      say("  hop %d: blocks %d -> descriptors %d, next %d",
         depth, len(frontier), len(cand), len(nxt))
      frontier = nxt
   }

   if len(frontier) > 0 {
      why = fmt.Sprintf("hop/block cap reached with %d blocks unexplored", len(frontier))
      say("")
      say("TRUNCATED: %s", why)
      say("  the candidate set below is incomplete, so a miss is not evidence of absence")
   }

   candList := make([]uint32, 0, len(cand))
   for d := range cand {
      candList = append(candList, d)
   }
   slices.Sort(candList)

   say("")
   say("stage candidates: %d descriptors, %d blocks visited in %d hops",
      len(candList), len(visited), depth)
   say("")
   if len(candList) == 0 {
      return nil, fmt.Errorf("no stage candidates - the lea/call idiom differs on this build")
   }

   prv, err := dpSampleKey()
   if err != nil {
      return nil, err
   }

   // ---- phase 1: every candidate as stage 1 --------------------------------
   type obfEnt struct {
      d1 uint32
      h  int
      o  int
      v  string
   }
   var obfs []obfEnt
   faulted := map[uint32]bool{}

   say("phase 1: %d candidates x 2 key halves", len(candList))
   for _, d := range candList {
      var ferr error
      var got []string
      for h := 0; h < 2; h++ {
         res, err := im.emu.call(d, keyLen, dpHalf(prv, h), make([]byte, keyLen), nil)
         if err != nil {
            ferr = err
            break
         }
         if !zero4(res.status) {
            continue
         }
         for o, v := range [2][]byte{res.key, res.out} {
            if isZeroHex(v) {
               continue
            }
            k := v[:keyLen]
            hx := hex.EncodeToString(k)
            obfs = append(obfs, obfEnt{d1: d, h: h, o: o, v: hx})
            got = append(got, fmt.Sprintf("half %d buf %d  %s", h, o, hx))
         }
      }
      switch {
      case ferr != nil:
         faulted[d] = true
         say("  0x%06x faults: %v", d, ferr)
      case len(got) == 0:
         say("  0x%06x REJECT for both halves", d)
      default:
         say("  0x%06x %d output(s)", d, len(got))
         for _, s := range got {
            say("      %s", s)
         }
      }
   }

   var obfList []obfEnt
   seen := map[string]bool{}
   for _, o := range obfs {
      if seen[o.v] {
         continue
      }
      seen[o.v] = true
      obfList = append(obfList, o)
   }
   say("")
   say("distinct OBFs: %d", len(obfList))
   say("")
   if len(obfList) == 0 {
      return nil, fmt.Errorf("no candidate produced a non-zero output for either key half\n" +
         "  stage 1 is not in the candidate set, or it rejects this sample's key")
   }

   // ---- phase 2: every non-faulting candidate as stage 2 -------------------
   var d2s []uint32
   for _, d := range candList {
      if !faulted[d] {
         d2s = append(d2s, d)
      }
   }
   say("phase 2: %d stage-2 candidates x %d OBFs x 2 key halves", len(d2s), len(obfList))
   say("")

   tab, _ := im.famTab(fam) // cmdDerive has already refused a family with no table

   for _, d2 := range d2s {
      var found *profileStages
      nMut := 0
      firstReject := ""
      faulted2 := false

      for _, o := range obfList {
         raw, err := hex.DecodeString(o.v)
         if err != nil || len(raw) != keyLen {
            continue
         }
         for h := 0; h < 2; h++ {
            res, err := im.emu.call(d2, keyLen, raw, dpHalf(prv, h), u32p(keyLen))
            if err != nil {
               say("  0x%06x faults on an OBF: %v", d2, err)
               faulted2 = true
               break
            }
            if !zero4(res.status) {
               if firstReject == "" {
                  firstReject = fmt.Sprintf("first reject st=%s  obf %s half %d",
                     hex.EncodeToString(res.status), o.v, h)
               }
               continue
            }
            nMut++
            for o2, buf := range [2][]byte{res.key, res.out} {
               plain, ok := dpChain(im.img, tab, buf[:keyLen])
               if !ok || !pubMatches(plain, want) {
                  continue
               }
               found = &profileStages{
                  S1: o.d1, K1: o.h, O1: o.o,
                  S2: d2, K2: h, O2: o2,
               }
               break
            }
            if found != nil {
               break
            }
         }
         if found != nil || faulted2 {
            break
         }
      }

      if found == nil {
         say("  0x%06x %d mut - no match", d2, nMut)
         if firstReject != "" {
            say("      %s", firstReject)
         }
         continue
      }

      // Confirm through the exact path this program will use: a candidate can produce a
      // match one call cannot reproduce, and a pairing that cannot be applied is not one.
      say("  0x%06x candidate match, confirming", d2)
      plain, err := applyPairing(im, fam, found, say)
      if err != nil || !pubMatches(plain, want) {
         say("  not reproducible - continuing")
         say("")
         continue
      }
      say("")
      say("MATCH")
      return found, nil
   }

   if why != "" {
      return nil, fmt.Errorf("no pairing found, but the walk was TRUNCATED - the search\n"+
         "  was not exhaustive, so this is not a conclusion (%s)", why)
   }
   return nil, fmt.Errorf("no (stage 1, stage 2) pairing reproduced %s\n"+
      "  %d stage-1 candidates produced %d distinct OBF(s); %d stage-2 candidates were\n"+
      "  tried against each, with both halves and both buffers.\n"+
      "  Nothing matched, so one of these is wrong:\n"+
      "    - stage 1 or stage 2 is outside the candidate set\n"+
      "    - stage 3/4 are not the consumer's table and permutation\n"+
      "    - %s does not hold this build's family %d table",
      encPubPath, len(candList), len(obfList), len(d2s), profilePath, fam)
}

// ---------------------------------------------------------------- the profile

// image is everything a call needs: the decrypted image, the census, the profile and one
// emulator over all of it.
type image struct {
   img      []byte
   prof     *dllProfile
   heaps    []imgDesc
   emu      *wbEmu
   captured bool
   base     uint64
}

func loadImage() (*image, error) {
   raw, err := os.ReadFile(profilePath)
   if err != nil {
      return nil, fmt.Errorf("no %s - run prkf -2 first", profilePath)
   }
   var p dllProfile
   if err := json.Unmarshal(raw, &p); err != nil {
      return nil, fmt.Errorf("%s: %v", profilePath, err)
   }
   if p.Census == nil || len(p.Census.Heaps) == 0 {
      return nil, fmt.Errorf("%s has no census - re-run prkf -2", profilePath)
   }

   im := &image{prof: &p}
   if im.img, err = os.ReadFile(imgPath); err != nil {
      return nil, fmt.Errorf("%s - run prkf -2: %v", imgPath, err)
   }
   if uint32(len(im.img)) != p.SizeOfImage {
      return nil, fmt.Errorf("%s is %d bytes but SizeOfImage is 0x%x - the image and the "+
         "profile are from different builds", imgPath, len(im.img), p.SizeOfImage)
   }

   blocks := map[uint32]emuRange{}
   for _, h := range p.Census.Heaps {
      d := imgDesc{va: h[0], descVA: h[1], rva: h[2], ln: h[3]}
      im.heaps = append(im.heaps, d)
      if d.ln != 0 && uint64(d.rva)+uint64(d.ln) <= uint64(len(im.img)) {
         blocks[d.va] = emuRange{rva: d.rva, ln: d.ln}
      }
   }
   im.emu = newWBEmu(im.img, blocks)

   // The capture is what lets stage 1 read the dispatch tables PlayReady built at runtime.
   if !isFile(memMapPath) || !isFile(memPath) {
      return im, nil
   }
   mraw, err := os.ReadFile(memMapPath)
   if err != nil {
      return nil, err
   }
   var mm memMapFile
   if err := json.Unmarshal(mraw, &mm); err != nil {
      return nil, fmt.Errorf("%s: %v", memMapPath, err)
   }
   if mm.DLLSHA256 != "" && mm.DLLSHA256 != p.DLLSHA256 {
      return nil, fmt.Errorf("%s was captured for DLL %s, not %s\n  re-run prkf -4 on "+
         "this build", memMapPath, mm.DLLSHA256, p.DLLSHA256)
   }
   data, err := os.ReadFile(memPath)
   if err != nil {
      return nil, err
   }
   if err := im.emu.loadCapture(&mm, data); err != nil {
      return nil, fmt.Errorf("%s: %v", memMapPath, err)
   }
   im.captured = true
   im.base = mm.ImageBase
   return im, nil
}

// famTab returns one family's stage 3/4 tables.
func (im *image) famTab(fam int) (*famTab, bool) {
   pm := im.prof.Map[vkey(fam)]
   if pm == nil {
      return nil, false
   }
   return &famTab{cluster: pm.Cluster, perm: pm.Map}, true
}

// derive.go end
