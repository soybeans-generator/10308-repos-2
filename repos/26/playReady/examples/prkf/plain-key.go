// plainkey.go begin
//go:build windows

// prkf -6: discover the (stage 1, stage 2) pairing for the sample's family if the profile
// does not already hold one, replay it, and write the encryption key.
//
//   stage 1  key half  --stage-1 routine-->  OBF
//   stage 2  OBF       --stage-2 routine-->  mut
//   stage 3  mut   --64 per-nibble bijection subtables-->  mapped
//   stage 4  mapped --16-entry permutation-->  plain
//
//   Proven by d*G == extracted.enc.pub. Nothing is written unless it holds.
//
// THIS STEP OWNS THE SEARCH: a candidate is accepted only when the scalar its chain produces
// satisfies d*G == extracted.enc.pub, and nothing local can stand in for that check, since a
// tuple verified against itself is consistent by construction. There is no sample before -4,
// so the search lives here, cached per family.
//
// STAGES 3 AND 4 ARE ONE PASS: mut is 32 bytes, so 64 nibbles. Nibble i selects one byte
// from its own 16-byte row at the family's cluster, and that byte - a value in 0..15 -
// indexes the 16-entry permutation. So `perm[img[cluster+i*16+nibble]]`, sixty-four times.
//
// key[0x40] % 3 selects one of three routine families, each with its own bijection table AND
// its own stage routines, so a search records only the family it was run for.
//
// Applying a pairing is two children - stage 1 then stage 2 - using the recorded key halves
// and buffers, the only combination that reproduces the sample's key.
package main

import (
   "crypto/sha256"
   "encoding/hex"
   "fmt"
   "os"
   "slices"
   "strconv"
)

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
   // failure would read as "produced no output". Both are checked against the only values a
   // trial row can carry.
   if !is01(st.K1) || !is01(st.O1) || !is01(st.K2) || !is01(st.O2) {
      return nil, fmt.Errorf("recorded pairing %+v has an index outside 0..1 - %s is corrupt",
         *st, profilePath)
   }

   // p1 runs both halves and prints both buffers, so the recorded half and buffer are picked
   // out of the two rows rather than requested.
   b1 := dpRunP1([]uint32{st.S1})
   if b1.loadfail != "" {
      return nil, fmt.Errorf("%s", b1.loadfail)
   }
   var obf []byte
   for _, r := range b1.res {
      if r.kind != "RES" || r.i%2 != st.K1 {
         continue
      }
      v, err := hex.DecodeString(r.buf[st.O1])
      if err != nil {
         // dpParse already proved this field is 0x40 hex characters, so this cannot fire
         // today. It stays on the same argument dpCommit re-runs pubMatches: the one place
         // that must not depend on a guarantee made in another file is the one that feeds
         // the next stage, because a prefix decode here is a different 0x20 bytes and every
         // verdict below it would read as "no match".
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
   if b2.loadfail != "" {
      return nil, fmt.Errorf("%s", b2.loadfail)
   }
   var mut []byte
   for _, r := range b2.res {
      if r.kind != "RES" || r.i%2 != st.K2 {
         continue
      }
      v, err := hex.DecodeString(r.buf[st.O2])
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
// An image byte above 0x0F means the cluster is not the table the profile says it is, which
// is a wrong profile rather than a wrong scalar, so it fails instead of masking.
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

// dpCommit is the one place a derived scalar becomes a file. The check is repeated here
// rather than trusted from the caller: this is the only write, so it is the only place a
// wrong scalar could reach the disk.
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

// dpSample returns the sample's 0x41-byte key component and its P-256 public key, carving
// them out of the BLA when -4 has not written them yet.
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
// carry. Every such index is read from dllprof.json, so it is checked rather than trusted.
func is01(v int) bool { return v == 0 || v == 1 }

// dpInputs is the profile plus the family tables -6 needs. The image, census, patch plan and
// parsed profile all come from pfImage, which is the same load a trial child does; prof is
// promoted from it rather than held a second time.
type dpInputs struct {
   *pfImage
   fams []int
   tab  map[int]*famTab
}

// dpLoadInputs validates the profile pfPrep already parsed and builds the per-family tables.
// It does NOT read dllprof.json a second time, and does NOT call scanDescs: the census in the
// profile is that scan's result.
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
   // still returned: the alternative is a silent map[0] that hides the two disagreeing, and
   // the rule is stated in kernel.go and used here.
   for k, pm := range pi.prof.Map {
      v, err := strconv.Atoi(k)
      if err != nil {
         return nil, fmt.Errorf("%s: map key %q is not a family index: %w",
            profilePath, k, err)
      }
      in.tab[v] = &famTab{cluster: pm.Cluster, perm: pm.Map}
      in.fams = append(in.fams, v)
   }
   slices.Sort(in.fams)
   return in, nil
}

// famTab is one family's stage 3/4 tables, taken from the profile's map section. The cluster
// and the permutation travel together because stage 4 needs both and a profile can only be
// valid when both came from the same family.
type famTab struct {
   cluster uint32
   perm    [16]int // mapped nibble -> real nibble
}

// plainkey.go end
