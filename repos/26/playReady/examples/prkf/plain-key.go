// plainkey.go begin
//go:build windows

// prkf -6: discover the (stage 1, stage 2) pairing for the sample's family if the
// profile does not already hold one, replay it, and write the encryption key.
//
//   stage 1  key half  --stage-1 routine-->  OBF
//   stage 2  OBF       --stage-2 routine-->  mut
//   stage 3  mut   --64 per-nibble bijection subtables-->  mapped
//   stage 4  mapped --16-entry permutation-->  plain
//
//   Proven by d*G == extracted.enc.pub. Nothing is written unless it holds.
//
// # THIS STEP OWNS THE SEARCH
//
// The search used to be a flag of its own, numbered before the carve step, and that
// could not work: every candidate is accepted only when the scalar its chain
// produces satisfies d*G == extracted.enc.pub, and nothing local can stand in for
// that check, since a tuple verified against itself is consistent by construction.
// There is no sample before -4, so the search lives here, cached per family, and the
// DLL phase is -1, -2 and -3.
//
// # STAGES 3 AND 4 ARE ONE PASS
//
// mut is 32 bytes, so 64 nibbles. Nibble i selects one byte from its own 16-byte
// row at the family's cluster, and that byte - a value in 0..15 - indexes the
// 16-entry permutation. So `mapt[img[cluster+i*16+nibble]]`, sixty-four times.
//
// The two stages used to be written as nibble-extract, table lookup, pack, nibble-
// extract again, permute, pack. The second extraction is the identity: packing then
// unpacking returns the same 64 nibbles. Writing it out as one pass removes an
// array and the chance of getting that identity wrong, which is exactly the bug one
// version had - it re-extracted from the packed bytes and read `mp[0]>>4` instead of
// `mp[0]`, so every scalar came out wrong and the search reported no pairing.
//
// key[0x40] % 3 selects one of three routine families, each with its own bijection
// table AND its own stage routines, so a search records only the family it was run
// for and a sample of a family this build has never seen pays for one search.
//
// Applying a pairing is two children - stage 1 then stage 2 - using the recorded
// key halves and buffers, which the search found to be the only combination that
// reproduces the sample's key. dpSample carves the key components out of
// msprcore.bla itself when -4 has not written them yet.
//
// USAGE  prkf -6. Children, positional: -6 p1 / -6 p2 (see stages.go).
package main

import (
   "bytes"
   "crypto/ecdh"
   "crypto/sha256"
   "encoding/hex"
   "fmt"
   "os"
   "slices"
   "strconv"
   "strings"
)

// dpApply replays a pairing and returns the scalar its chain produces. Two children
// - p1 for stage 1, p2 for stage 2 - because those are the only trial modes there
// are. Stages 3 and 4 are pure table work, so they run here.
//
// It uses the recorded key halves and buffers, not defaults: those were discovered
// by the search and are the only combination that reproduces the sample's key.
func dpApply(in *dpInputs, fam int, st *profileStages, say func(string, ...any)) ([]byte, error) {
   say("family %d  cluster 0x%06x", fam, in.cluster[fam])
   say("stage 1  0x%06x  key half %d  out buffer %d", st.S1, st.K1, st.O1)
   say("stage 2  0x%06x  key half %d  out buffer %d", st.S2, st.K2, st.O2)
   say("")

   // p1 runs both halves and prints both buffers, so the recorded half and buffer
   // are picked out of the two rows rather than requested.
   b1 := dpRunP1([]uint32{st.S1})
   if b1.loadfail != "" {
      return nil, fmt.Errorf("%s", b1.loadfail)
   }
   var obf []byte
   for _, r := range b1.res {
      if r.kind != "RES" || r.h != st.K1 {
         continue
      }
      obf, _ = hex.DecodeString([2]string{r.a, r.b}[st.O1])
   }
   if len(obf) != 0x20 {
      return nil, fmt.Errorf("stage 1 (0x%06x, half %d) produced no output\n"+
         "  the pairing does not apply to this build", st.S1, st.K1)
   }
   say("  obf       %x", obf)

   b2 := dpRunP2(0, []dpObf{{v: hex.EncodeToString(obf)}}, []uint32{st.S2})
   if b2.loadfail != "" {
      return nil, fmt.Errorf("%s", b2.loadfail)
   }
   var mut []byte
   for _, r := range b2.res {
      if r.kind != "RES" || r.i%2 != st.K2 {
         continue
      }
      mut, _ = hex.DecodeString([2]string{r.a, r.b}[st.O2])
   }
   if len(mut) != 0x20 {
      return nil, fmt.Errorf("stage 2 (0x%06x, half %d) produced no output", st.S2, st.K2)
   }
   say("  mut       %x", mut)

   plain, ok := dpChain(in.img, in.cluster[fam], in.mapt[fam], mut)
   if !ok {
      return nil, fmt.Errorf("stages 3 and 4 could not be applied - re-run prkf -3")
   }
   say("  plain     %x", plain)
   return plain, nil
}

// dpChain applies stages 3 and 4 in one pass.
//
// mut is 32 bytes, so 64 nibbles, high nibble first. Nibble i selects one byte from
// its own 16-byte row at the family's cluster - a value in 0..15 - and that value
// indexes the 16-entry permutation. The packed form is rebuilt at the end.
//
// The two stages were once written as nibble-extract, lookup, pack, nibble-extract,
// permute, pack. The second extraction is the identity, so collapsing it removes an
// array and a place to get that identity wrong; a version that kept it re-extracted
// from the packed bytes and read mp[0]>>4 instead of mp[0], which broke every scalar.
func dpChain(img []byte, cluster uint32, mapt map[int]int, mut []byte) ([]byte, bool) {
   if len(mut) < 0x20 {
      return nil, false
   }
   c := int(cluster)
   if c < 0 || c+64*16 > len(img) {
      return nil, false
   }

   var ns, pl [64]byte
   for i := range ns {
      sh := uint(0)
      if i%2 == 0 {
         sh = 4
      }
      ns[i] = mut[i>>1] >> sh & 0xF
   }
   for i := range pl {
      v, ok := mapt[int(img[c+i*16+int(ns[i])])]
      if !ok {
         return nil, false
      }
      pl[i] = byte(v)
   }

   out := make([]byte, 32)
   for i := 0; i < 64; i += 2 {
      out[i/2] = pl[i]<<4 | pl[i+1]
   }
   return out, true
}

// dpCommit is the one place a derived scalar becomes a file. The check is repeated
// here rather than trusted from the caller: this is the only write, so it is the
// only place a wrong scalar could reach the disk.
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
   defer func() {
      if err := os.WriteFile(plainLogPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
         fmt.Fprintf(os.Stderr, "prkf: %s: %v\n", plainLogPath, err)
         if code == 0 {
            code = 1
         }
      }
   }()

   in, err := dpLoadInputs()
   if err != nil {
      return fail("%v", err)
   }

   // The sample: the pairing is found by running a real key through the stages and
   // verified by d*G == extracted.enc.pub, and a synthetic key cannot be used
   // because the routines reject it.
   prv, pub, err := dpSample()
   if err != nil {
      return fail("%v", err)
   }
   fam := int(prv[0x40]) % 3
   if _, ok := in.mapt[fam]; !ok {
      return fail("%s selects routine family %d, but %s holds only %v\n"+
         "  that family produced no live set on this build: re-run prkf -3",
         encPrvPath, fam, profilePath, in.fams)
   }

   say("dll    %s", in.sha)
   say("image  %s  (%d bytes, SizeOfImage 0x%x)", imgPath, len(in.img), in.sizeImg)
   say("prv    %s  family %d (key[0x40]=0x%02x %%3)", encPrvPath, fam, prv[0x40])
   say("pub    %s", encPubPath)
   say("")

   st := in.prof.Stages[vkey(fam)]
   if st == nil {
      // A family this build has no pairing for. Discover it with this sample, then
      // cache it, so every later sample of this family is instant.
      say("no stage pairing for family %d - discovering it with this sample", fam)
      say("")
      if st, err = dpFindStages(in, fam, pub, say); err != nil {
         return fail("%v", err)
      }
      // Assigned, not replaced: the stage routines are selected by the same byte as
      // the bijection table, so this search says nothing about another family, and
      // dropping a pairing already cached for one would cost it a search.
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

// dpSample returns the sample's 0x41-byte key component and its P-256 public key,
// carving them out of the BLA when -4 has not written them yet.
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

// pubBytes normalizes a stored public key to the 65-byte SEC 1 form. The key files
// carry X||Y with no prefix, so that is the only difference to absorb. nil means
// the point is off the curve or at infinity, which NewPublicKey rejects.
func pubBytes(raw []byte) []byte {
   if len(raw) == 64 {
      raw = append([]byte{4}, raw...)
   }
   k, err := ecdh.P256().NewPublicKey(raw)
   if err != nil {
      return nil
   }
   return k.Bytes()
}

// --- the one P-256 check ----------------------------------------------------

// d*G == Q is the pipeline's only end-to-end proof: a wrong stage descriptor, key
// half, buffer choice or permutation cannot produce a scalar whose public point
// lands on the expected key. -5 and -6 both assert it, so it is written once here
// rather than twice with two opinions about the 0x04 prefix.

// pubFor returns d*G as 0x04||X||Y, or nil when d is not a valid P-256 scalar. The
// range check is NewPrivateKey's: d >= N or a wrong length fails there rather than
// being caught by hand.
func pubFor(d []byte) []byte {
   priv, err := ecdh.P256().NewPrivateKey(d)
   if err != nil {
      return nil
   }
   return priv.PublicKey().Bytes()
}

// pubMatches reports whether d*G is the public key in raw, in either form. A nil
// from either helper is a mismatch, never an accidental equal: bytes.Equal treats
// two empty slices as equal, so the nils are checked first.
func pubMatches(d, raw []byte) bool {
   got, want := pubFor(d), pubBytes(raw)
   return got != nil && want != nil && bytes.Equal(got, want)
}

// --- stage entry point ------------------------------------------------------

// stageDerivePlain is -6's entry point. A positional argument makes this process one
// of the search's trial children; its stdout is parsed, so it exits on the raw code.
func stageDerivePlain(args []string) int {
   if len(args) > 0 {
      return dpTrialChild(args)
   }
   return dpDerive()
}

// ---------------------------------------------------------------- the inputs

type dpInputs struct {
   img     []byte
   sha     string
   sizeImg uint32
   prof    *dllProfile
   fams    []int
   heaps   []imgDesc
   seg     []imgSpan
   merged  []imgInterval
   cluster map[int]uint32
   mapt    map[int]map[int]int
}

// dpLoadInputs reads what the driver needs: the profile, the image, and the census.
// It does NOT call scanDescs - the census in the profile is that scan's result, and
// re-running it here would cost the same several gigabytes it costs in -2.
//
// The census heap entry is {va, descVA, codeRVA, codeLen} and all four must be read:
// a version that read it as {descVA, rva, ln} left every descriptor with va == 0,
// collapsed them onto one map key, and reported "1 heap-exec descriptor".
func dpLoadInputs() (*dpInputs, error) {
   in := &dpInputs{
      cluster: map[int]uint32{},
      mapt:    map[int]map[int]int{},
   }
   var err error

   _, in.sha, err = pfDLL()
   if err != nil {
      return nil, err
   }
   if in.prof, err = pfRequire(in.sha); err != nil {
      return nil, err
   }
   for k, pm := range in.prof.Map {
      v, verr := strconv.Atoi(k)
      if verr != nil {
         return nil, fmt.Errorf("%s: bad family key %q", profilePath, k)
      }
      m := make(map[int]int, len(pm.Map))
      for mk, mv := range pm.Map {
         mi, merr := strconv.Atoi(mk)
         if merr != nil {
            return nil, fmt.Errorf("%s: bad map key %q", profilePath, mk)
         }
         m[mi] = mv
      }
      in.cluster[v] = pm.Cluster
      in.mapt[v] = m
      in.fams = append(in.fams, v)
   }
   slices.Sort(in.fams)

   if in.prof.Census == nil || len(in.prof.Census.Heaps) == 0 {
      return nil, fmt.Errorf("%s has no census - re-run prkf -2", profilePath)
   }
   if in.img, err = os.ReadFile(imgPath); err != nil {
      return nil, err
   }
   in.sizeImg = in.prof.SizeOfImage
   if uint32(len(in.img)) != in.sizeImg {
      return nil, fmt.Errorf("%s is %d bytes but this build's SizeOfImage is 0x%x - run prkf -2",
         imgPath, len(in.img), in.sizeImg)
   }

   for _, h := range in.prof.Census.Heaps {
      in.heaps = append(in.heaps, imgDesc{va: h[0], descVA: h[1], rva: h[2], ln: h[3]})
   }
   for _, s := range in.prof.Census.Spans {
      in.seg = append(in.seg, imgSpan{rva: s[0], size: s[1]})
   }
   in.merged = mergeIntervals(heapIntervals(in.heaps))
   return in, nil
}

// plainkey.go end
