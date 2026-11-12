// nibblemap.go begin
//go:build windows

// prkf -3: magic-independent stage 3 of the nibble chain, and the oracle it measures with.
// The decrypted image plus the oracle licences become one permutation per routine family.
//
// THE LIVE-SET TEST NEEDS ONE LICENCE. Forcing the table to a constant m makes the derived
// scalar 32 bytes of 0x11*MAP[m], so the consumer's output depends on m only through
// MAP[m]. A set the routine reads yields 16 DISTINCT outputs for one licence; a set it
// never reads yields 16 identical ones.
//
// THE PERMUTATION NEEDS FIFTEEN. On the live set, for every real nibble NN exactly one
// forced m reaches the sentinel, and the sentinel output is the same 32 bytes for every
// licence. So the value shared by all 15 licences is SENT XOR magic, and magic is recovered
// rather than assumed.
//
// NO SAMPLE IS READ: any 0x41 bytes drive the routine, because forcing the table collapses
// whatever it derives. Byte 0x40 is the family selector, so all three families are swept
// and each live one is cached.
//
// ONE CHILD FOR ALL THREE FAMILIES, because the module load, image read and span patch that
// precede its first probe dwarf the rest. The census comes from the profile, so this step
// never reads the DLL.
//
// OUTPUT IS HEX, ALWAYS: a raw-bytes %s would let a result containing 0x20 corrupt the
// driver's whitespace split, and only for some values.
//
// # THE ORACLE
//
// Not a step. Built here on demand when testdata/oracle is absent; it reads neither base
// file, is derived from a fixed sentinel and fixed scalars, and never needs regenerating
// (`rm -rf testdata/oracle` forces a rebuild).
//
// For each key nibble N in 0x01..0x0f it writes key_NN.pub (the public key whose private
// scalar has every nibble = N) and lic_NN.blob (an ECIES blob for that key whose plaintext
// is "HELLO MICROSOFT!" || 0^16). Nibble 0x00 is skipped: scalar 0 is not a valid private
// key, and -3 recovers that entry as the leftover.
//
// THE SCALAR IS NIBBLES, NOT BYTES: forcing the table to M makes every NIBBLE of the
// derived scalar M, so that scalar is 32 bytes of 0x11*M.
//
// INPUTS   profilePath (census), imgPath, oracleDir/lic_NN.blob
// OUTPUT   profilePath's map section, keyed by family; mapLogPath
package main

import (
   "bytes"
   "crypto/ecdh"
   "crypto/rand"
   "encoding/hex"
   "fmt"
   "os"
   "path/filepath"

   "filippo.io/nistec"
)

// dmFams is every routine family the consumer dispatches on: key[0x40] % 3. It is one
// value read by both the sweep and the loop that consumes its rows, so the count cannot
// drift between them.
var dmFams = []int{0, 1, 2}

// =============================================================================
// the oracle
// =============================================================================

// moSentinel is the plaintext every oracle licence encrypts: "HELLO MICROSOFT!" || 0^16.
// Defined once because two things must agree on it byte for byte - the X coordinate the
// oracle puts on the curve, and the value -3 XORs the shared output with to recover the
// magic.
var moSentinel = append([]byte("HELLO MICROSOFT!"), make([]byte, 16)...)

// buildOracle writes the 15 key+licence pairs into oracleDir. Called by -3 when the
// directory is missing. Its stdout goes straight to the terminal and is not folded into
// derive_map.txt: the build is a one-time setup event.
func buildOracle() int {
   // 0x02||X is the compressed SEC 1 form, and the 0x02 prefix asks for the even root, so
   // the Y below is stable across runs. SetBytes is the whole check: it decompresses the
   // point and rejects an X that is not on the curve.
   m, err := nistec.NewP256Point().SetBytes(append([]byte{0x02}, moSentinel...))
   if err != nil {
      return moFail("'HELLO MICROSOFT!' || 0^16 is not an x-coordinate on P-256: %v", err)
   }
   mb := m.Bytes() // 0x04 || X || Y

   if err := os.MkdirAll(oracleDir, 0o755); err != nil {
      return moFail("create %s: %v", oracleDir, err)
   }
   if abs, err := filepath.Abs(oracleDir); err == nil {
      fmt.Printf("output    %s\n", abs)
   } else {
      fmt.Printf("output    %s\n", oracleDir)
   }
   fmt.Printf("sentinel  X = %x\n", mb[1:33])
   fmt.Printf("          Y = %x\n", mb[33:])
   fmt.Printf("\n")

   // Distinct public keys are the oracle's whole output: a collision would silently
   // overwrite one nibble's key with another's.
   pubs := make(map[string]bool)

   for nib := 1; nib < 16; nib++ {
      // The private scalar: nibble NN repeated 64 times, which is 32 bytes of 0x11*NN. No
      // reduction is possible or needed: the largest, 0x0f, is (2^256-1)/17, below N, so all
      // fifteen are already valid scalars.
      k := bytes.Repeat([]byte{byte(nib * 0x11)}, 32)

      q, err := nistec.NewP256Point().ScalarBaseMult(k)
      if err != nil {
         return moFail("nibble %02x: ScalarBaseMult: %v", nib, err)
      }

      // key file: X||Y, no 0x04 prefix, exactly what .sig.pub/.enc.pub use
      pub, err := moXY(nib, "public key", q)
      if err != nil {
         return moFail("%v", err)
      }
      if pubs[string(pub)] {
         return moFail("nibble %02x duplicates an earlier public key", nib)
      }
      pubs[string(pub)] = true
      if err := os.WriteFile(filepath.Join(oracleDir, fmt.Sprintf("key_%02x.pub", nib)), pub, 0o644); err != nil {
         return moFail("write key_%02x.pub: %v", nib, err)
      }

      // licence blob: ECIES  C1 = r*G,  C2 = M + r*Q. Decryption with scalar k gives
      // C2 - k*C1 = M, so the plaintext point's X-coordinate is the sentinel and the
      // routine's output is SENT XOR magic.
      r, err := moRandScalar()
      if err != nil {
         return moFail("%v", err)
      }
      c1, err := nistec.NewP256Point().ScalarBaseMult(r)
      if err != nil {
         return moFail("nibble %02x: C1 = r*G: %v", nib, err)
      }
      rq, err := nistec.NewP256Point().ScalarMult(q, r)
      if err != nil {
         return moFail("nibble %02x: r*Q: %v", nib, err)
      }
      c2 := nistec.NewP256Point().Add(m, rq)

      c1b, err := moXY(nib, "C1", c1)
      if err != nil {
         return moFail("%v", err)
      }
      c2b, err := moXY(nib, "C2", c2)
      if err != nil {
         return moFail("%v", err)
      }
      blob := make([]byte, 0, 0x80)
      blob = append(blob, c1b...)
      blob = append(blob, c2b...)
      if len(blob) != 0x80 {
         return moFail("nibble %02x: blob is %d bytes", nib, len(blob))
      }
      if err := os.WriteFile(filepath.Join(oracleDir, fmt.Sprintf("lic_%02x.blob", nib)), blob, 0o644); err != nil {
         return moFail("write lic_%02x.blob: %v", nib, err)
      }

      // Round-trip: k*C1 + M must be C2, which is C2 - k*C1 = M written without a negation.
      // k is the unreduced scalar the routine will actually compute.
      kc1, err := nistec.NewP256Point().ScalarMult(c1, k)
      if err != nil {
         return moFail("nibble %02x: k*C1: %v", nib, err)
      }
      if rec := nistec.NewP256Point().Add(kc1, m); !bytes.Equal(rec.Bytes(), c2.Bytes()) {
         return moFail("nibble %02x: round-trip did not recover the sentinel point", nib)
      }

      fmt.Printf("%02x  d = %x\n    X %x\n    Y %x\n    key 0x40 bytes  blob 0x80 bytes  round-trip OK\n",
         nib, k, pub[:32], pub[32:])
   }

   if len(pubs) != 15 {
      return moFail("only %d distinct public keys, expected 15", len(pubs))
   }

   fmt.Printf("\ngenerated %d/15 key+licence pairs in %s\n", len(pubs), oracleDir)
   fmt.Printf("key_NN.pub is deterministic; lic_NN.blob is not (random ephemeral scalar).\n")
   return 0
}

// dmDeriveMap is the driver. The log is written by the deferred Finish, so no return can
// leave it unwritten.
func dmDeriveMap() (code int) {
   lg := newStepLog(mapLogPath)
   defer lg.Finish(&code)
   logf, fail := lg.Printf, lg.Failf

   // The census and the image come from the profile, so this step never reads the DLL:
   // scanDescs already ran in -2.
   pi, err := pfPrep()
   if err != nil {
      return fail("%v", err)
   }

   if _, err := os.Stat(oracleDir); err != nil {
      logf("oracle %s is missing - building it (one time, ever)", oracleDir)
      if oc := buildOracle(); oc != 0 {
         return fail("oracle build failed (exit %d)", oc)
      }
      logf("")
   }

   logf("dll      %s", pi.sha)
   logf("image    %s  %d bytes  SizeOfImage 0x%x", imgPath, len(pi.img), pi.size)
   logf("spans    %d  heap-exec %d", len(pi.spans), len(pi.heaps))
   logf("")

   SETS := dmFindSets(pi.img)
   logf("bijection sets: %d", len(SETS))
   for i, rva := range SETS {
      logf("  set%d  0x%06x  %x", i, rva, pi.img[rva:min(rva+16, uint32(len(pi.img)))])
   }
   logf("")
   if len(SETS) == 0 {
      return fail("no permutation sets found - is wbtool_img.bin decrypted?")
   }

   h, site, ok := dmFindConsumer(pi.img, pi.heaps)
   if !ok {
      return fail("consumer size-check site not unique (%#x)", site)
   }
   logf("consumer descriptor 0x%06x  site 0x%x", h.descVA, site)
   logf("")

   // The child decides which set is live and then sweeps it over 15 licences. Nothing about
   // that decision needs the driver, so the whole sweep is one process and one image patch.
   logf("sweeping %d families in one child", len(dmFams))
   logf("")

   r := dmSweepAll(h.descVA, dmFams, SETS, logf)
   for _, m := range r.meta {
      logf("  %s", m)
   }
   if r.loadfail != "" {
      return fail("%s", r.loadfail)
   }
   if r.fault != "" {
      logf("  %s", r.fault)
   }
   logf("")

   pmaps := map[string]*profileMap{}

   for _, v := range dmFams {
      fm := r.fams[v]
      if fm == nil {
         logf("family %d  no rows returned", v)
         continue
      }
      if fm.nLive != 1 {
         logf("family %d  %d live sets, expected 1 - skipped", v, fm.nLive)
         logf("")
         continue
      }
      logf("family %d  live set 0x%06x", v, fm.liveRVA)

      MAP, shared, err := dmPerm(fm)
      if err != nil {
         logf("          %v", err)
         logf("")
         continue
      }
      mh, herr := hex.DecodeString(shared)
      if herr != nil || len(mh) != len(moSentinel) {
         logf("          shared value is not %d hex bytes: %q", len(moSentinel), shared)
         logf("")
         continue
      }
      MAGIC := make([]byte, len(moSentinel))
      for i := range MAGIC {
         MAGIC[i] = mh[i] ^ moSentinel[i]
      }

      switch {
      case bytes.Equal(MAGIC, dmHx("a77bece491a87ebcd8a2c62856b165b33ad2572cf88bdae3ddc79be816be3185")):
         logf("          magic %x == the Windows 10 sequence", MAGIC)
      case bytes.Equal(MAGIC, dmHx("c3cd57691eff156c95d946d534121dfb81738adb5b4bb4223faad89cbb459bec")):
         logf("          magic %x == the Windows 11 sequence", MAGIC)
      default:
         logf("          magic %x == NEITHER published sequence: this build uses a third", MAGIC)
      }
      logf("          [MAP]  mapped -> real")
      for m := 0; m < 16; m++ {
         logf("            %x -> %x", m, MAP[m])
      }
      logf("")

      pmaps[vkey(v)] = &profileMap{
         Cluster:  fm.liveRVA,
         Magic:    hex.EncodeToString(MAGIC),
         Map:      MAP,
         Consumer: h.descVA,
      }
   }

   if len(pmaps) == 0 {
      return fail("no routine family produced a live set")
   }
   logf("families with a permutation: %d of %d", len(pmaps), len(dmFams))
   logf("")

   // pfLoad, not a fresh profile: -3 fills in one section and must not disturb a stage
   // pairing -6 may already have written.
   p := pfLoad(pi.sha)
   p.SizeOfImage = pi.size
   p.Map = pmaps
   if err := pfSave(p); err != nil {
      return fail("%v", err)
   }
   logf("written %s (map section)", profilePath)
   return 0
}

// dmFindSets finds every run of bytes <= 0x0f long enough to hold a bijection set, and
// within each run every offset where 64 consecutive 16-byte rows are each a permutation of
// 0..15.
func dmFindSets(img []byte) []uint32 {
   const (
      cblk = 16 // bytes per subtable row
      cn   = 64 // rows per set
   )
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
      for o := lo; o+dmCLEN <= i; {
         j := 0
         for ; j < cn; j++ {
            if !dmUniq(img[o+j*cblk : o+(j+1)*cblk]) {
               break
            }
         }
         if j == cn {
            out = append(out, uint32(o))
            o += dmCLEN
         } else {
            o++
         }
      }
   }
   return out
}

// dmHx parses a hex constant. A malformed constant is a programming error, and silently
// returning nil would make the Windows 10/11 comparisons false for the wrong reason, so it
// panics at the comparison site.
func dmHx(s string) []byte {
   b, err := hex.DecodeString(s)
   if err != nil {
      panic("dmHx: bad hex constant: " + s)
   }
   return b
}

// dmPerm builds one family's permutation from a completed sweep. The value every licence
// agrees on is the sentinel output, SENT XOR magic; the forced nibble that produced it is
// the pre-image of that licence's real nibble, so reading the hits out in licence order
// gives MAP inverted, which is what stage 4 wants.
//
// It returns the permutation directly rather than a map: -1 marks "not yet claimed", which
// is also how the single leftover is found.
func dmPerm(fm *dmFam) ([16]int, string, error) {
   var MAP [16]int
   for i := range MAP {
      MAP[i] = -1
   }
   if len(fm.outs) < 15 {
      return MAP, "", fmt.Errorf("sweep incomplete (%d of 15 licences)", len(fm.outs))
   }

   cnt := map[string]int{}
   for _, m := range fm.outs {
      seen := map[string]bool{}
      for _, x := range m {
         seen[x] = true
      }
      for x := range seen {
         cnt[x]++
      }
   }
   var shared []string
   for x, c := range cnt {
      if c == len(fm.outs) {
         shared = append(shared, x)
      }
   }
   if len(shared) != 1 {
      return MAP, "", fmt.Errorf("%d values shared by all %d licences, expected 1",
         len(shared), len(fm.outs))
   }
   magic := shared[0]

   for nn := 1; nn < 16; nn++ {
      var hits []int
      for mm, x := range fm.outs[nn] {
         if x == magic {
            hits = append(hits, mm)
         }
      }
      if len(hits) != 1 {
         return MAP, "", fmt.Errorf("nibble 0x%x: %d hits, expected 1", nn, len(hits))
      }
      if p := MAP[hits[0]]; p >= 0 {
         return MAP, "", fmt.Errorf("mapped 0x%x claimed by real 0x%x and 0x%x", hits[0], p, nn)
      }
      MAP[hits[0]] = nn
   }

   // Exactly one forced nibble is left: 0x00, which no licence exercises because scalar 0 is
   // not a valid private key.
   left := -1
   for m := 0; m < 16; m++ {
      if MAP[m] < 0 {
         if left >= 0 {
            return MAP, "", fmt.Errorf("expected one leftover, got 0x%x and 0x%x", left, m)
         }
         left = m
      }
   }
   if left < 0 {
      return MAP, "", fmt.Errorf("expected one leftover, got none")
   }
   MAP[left] = 0
   return MAP, magic, nil
}

func dmUniq(b []byte) bool {
   var seen [256]bool
   for _, c := range b {
      if seen[c] {
         return false
      }
      seen[c] = true
   }
   return true
}

// moFail reports a fatal condition on stderr and yields exit code 1.
func moFail(format string, args ...any) int {
   fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
   return 1
}

// moRandScalar draws a uniform non-zero scalar mod N. crypto/ecdh owns that distribution,
// so neither the retry loop nor the zero test is repeated here.
func moRandScalar() ([]byte, error) {
   k, err := ecdh.P256().GenerateKey(rand.Reader)
   if err != nil {
      return nil, fmt.Errorf("generate ephemeral scalar: %w", err)
   }
   return k.Bytes(), nil
}

// moXY returns a point as X||Y, the 64-byte form every PlayReady key file uses. An infinity
// result has no 65-byte encoding and is an error here rather than silently written as 64
// zero bytes.
func moXY(nib int, what string, p *nistec.P256Point) ([]byte, error) {
   b := p.Bytes()
   if len(b) != 65 || b[0] != 4 {
      return nil, fmt.Errorf("nibble %02x: %s is the identity", nib, what)
   }
   return b[1:], nil
}

// dmFindConsumer returns the heap-exec descriptor owning the unique size-check site and the
// site itself, so the driver does not look it up a second time.
//
// The descriptor comes back by pointer to match every other imgDesc parameter, and &h is
// safe because Go 1.22 makes the loop variable per-iteration: the caller gets its own
// 24-byte copy and cannot alias a row of the census it was derived from.
func dmFindConsumer(img []byte, heaps []imgDesc) (*imgDesc, int, bool) {
   site := bytes.Index(img, dpPattern)
   if site < 0 || bytes.Count(img, dpPattern) != 1 {
      return nil, site, false
   }
   for _, h := range heaps {
      if h.ln != 0 && int(h.rva) <= site && site < int(h.rva+h.ln) {
         return &h, site, true
      }
   }
   return nil, site, false
}

// nibblemap.go end
