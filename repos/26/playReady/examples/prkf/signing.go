// signing.go begin
//go:build windows

// prkf -2 and -3: find the signing-key routine's descriptor, then decrypt the
// signing key with it. One file, because -2 writes prsubs.json and -3 reads
// it, both call the same ABI in warbird.go, and both name the same DLL.
//
// -2 scans the DLL for Warbird heap-exec descriptors, then re-executes this
// binary once per candidate, eight at a time, and reads the RESULT line each
// child prints. Discovery rests entirely on properties of the routine itself,
// read from its disassembly - no sample key files:
//
//  1. accepts exactly 0x20 bytes and succeeds
//     (it begins: cmp dword ptr [rcx+10h], 20h)
//  2. writes its output buffer; 3. different input -> different output
//  4. REJECTS a size other than 0x20
//
// Property 4 is the discriminating one - it collapses the large set of
// descriptors that merely return success. Verification against a real key is
// -3's job, not -2's. Zero accepted descriptors, or more than one, is an error
// to investigate: there is no fallback path. Outputs: prsubsPath (build values,
// keyed by the DLL sha256) and scanLogPath (probe results and child traces).
//
// DIAGNOSTICS. A scan that stalls has three possible shapes - one child
// spinning, several spinning, or the parent deadlocked - and the progress line
// cannot tell them apart. The log can: `job N start/end` per descriptor with
// wall clock, `trace[i desc]` streamed live, and `watchdog` every 5s naming the
// descriptors still in flight and for how long. A stuck descriptor leaves its
// last trace line as the final record for that index: `probe B begin` means the
// child never returned from the kernel call for probe B. There is no deadline,
// so interrupt the run and read the log. If work is in flight but the watchdog
// never names a growing duration, the parent is stuck rather than a child;
// Ctrl-Break prints a goroutine dump by itself.
//
// NOTE: dllPath is in main.go's manifest; descTotal's 0xF0 test, scanDescs and
// splitDescs are in warbird.go; the child this driver spawns, and the
// PRKF_PROBE_DESC variable that selects it, are in child.go.
//
// -3 decrypts sigPrvPath -> sigPlainPath, writing output only after every
// available check passes.
//
// VERSION SUPPORT. Only ONE value differs between DLL builds: the RVA of the
// heap descriptor holding the signing-key routine, from prsubsPath keyed by the
// DLL sha256. This step refuses to run if the cache does not match the DLL.
//
// Everything else is hardcoded because it cannot drift with the DLL: op=3 and
// the WarbirdCallArgs layout are kernel ABI; the routine's own argument struct
// is packed (it reads its output pointer unaligned at +0x14) and packed layout
// is fixed by source; size == 0x20 is the P-256 scalar length, which the
// routine tests itself.
//
// VERIFICATION. The check needs no secret reference: the plaintext d must
// satisfy d*G == Q, where Q is the P-256 public key -1 wrote next to the
// ciphertext. A wrong descriptor, output offset, argument layout or input file
// cannot produce a scalar whose public point lands on Q. NewPublicKey and
// NewPrivateKey do the on-curve and range checks, so neither is repeated.
//
// Failure is loud, never silent: wrong desc_va -> NTSTATUS 0xC0000095
// (INTEGER_OVERFLOW); wrong arg layout -> status dword 0x80070057
// (E_INVALIDARG) plus an unwritten output buffer; output == input -> wrong
// routine; d*G != sig.pub -> descriptor, argument layout or input is wrong.
//
// NOTE: keyLen, statusOK, wbArgs, newWbArgs, loadWarbird and callWarbird are
// in warbird.go. This half imports neither unsafe nor syscall: the one pointer
// conversion and the one module load are inside warbird.go.
package main

import (
   "bytes"
   "crypto/ecdh"
   "crypto/rand"
   "crypto/sha256"
   "encoding/hex"
   "encoding/json"
   "errors"
   "fmt"
   "os"
   "sort"
   "strconv"
   "strings"
   "sync"
   "time"
)

// ------------------------------------------------------------ -3: decrypt

func cmdDecrypt() error {
   if !isFile(sigPrvPath) {
      return fmt.Errorf("missing input: %s\n  run prkf -1 first", sigPrvPath)
   }
   if !isFile(sigPubPath) {
      return fmt.Errorf("missing public key: %s\n  run prkf -1 first", sigPubPath)
   }

   // ---- decrypt ------------------------------------------------------
   got, err := decryptSigningKey(sigPrvPath)
   if err != nil {
      return err
   }
   fmt.Printf("%s (%d bytes)\n", sigPrvPath, len(got))
   fmt.Printf("plaintext %s\n", hex.EncodeToString(got))

   // ---- validation: d*G must equal the published public key ----------
   raw, err := os.ReadFile(sigPubPath)
   if err != nil {
      return err
   }
   // Normalize to the uncompressed 65-byte SEC 1 form. NewPublicKey accepts
   // the uncompressed and compressed encodings and rejects anything off the
   // curve or at infinity, so the on-curve check is not repeated here.
   if len(raw) == 64 { // raw x||y: add the uncompressed prefix
      raw = append([]byte{0x04}, raw...)
   }
   k, err := ecdh.P256().NewPublicKey(raw)
   if err != nil {
      return fmt.Errorf("%s: P-256 point: %v", sigPubPath, err)
   }
   want := k.Bytes()

   // An out-of-range d makes NewPrivateKey fail, leaving gotPub nil, which
   // falls through to the same verdict as a mismatched point.
   var gotPub []byte
   if priv, err := ecdh.P256().NewPrivateKey(got); err == nil {
      gotPub = priv.PublicKey().Bytes()
   }
   if !bytes.Equal(gotPub, want) {
      return fmt.Errorf("d*G != %s - the plaintext is not the private key for\n"+
         "that public key; the descriptor, the argument layout or the\n"+
         "input file is wrong; nothing was written", sigPubPath)
   }
   fmt.Printf("[ OK ] d*G == %s\n", sigPubPath)
   fmt.Printf("       Q = (%s,\n            %s)\n",
      hex.EncodeToString(want[1:33]), hex.EncodeToString(want[33:65]))

   // ---- write --------------------------------------------------------
   if err := os.WriteFile(sigPlainPath, got, 0o666); err != nil {
      return err
   }
   fmt.Printf("\nwrote %s (%d bytes)\n", sigPlainPath, len(got))
   return nil
}

// cmdFindSub is the entry point for prkf -2.
func cmdFindSub() error {
   // Taken before the DLL is read so the reported total covers the whole
   // step: read, PE parse, descriptor scan, every probe, and the write.
   start := time.Now()

   data, err := os.ReadFile(dllPath)
   if err != nil {
      return err
   }
   sum := sha256.Sum256(data)
   shaHex := hex.EncodeToString(sum[:])

   logf, err := os.Create(scanLogPath)
   if err != nil {
      return err
   }
   // Checked, and checked before the elapsed line runs: the header calls this
   // log the only evidence a stalled scan leaves behind, so a close that fails
   // (a full disk is the common case) must not be silent.
   defer func() {
      if err := logf.Close(); err != nil {
         fmt.Fprintf(os.Stderr, "prkf -2: %s: close: %v\n", scanLogPath, err)
      }
   }()
   // *os.File writes are unbuffered, so each line reaches the log as soon as
   // it is written - useful when the scan dies partway through. logMu exists
   // because the workers and the watchdog both write; logErr keeps the first
   // write failure, because a log that stops mid-scan is worse than one that
   // says so.
   var (
      logMu  sync.Mutex
      logErr error
   )
   w := func(s string) {
      logMu.Lock()
      if logErr == nil {
         if _, err := fmt.Fprintln(logf, s); err != nil {
            logErr = err
         }
      }
      logMu.Unlock()
   }

   // Deferred, not printed inline: the error returns below (zero accepted,
   // ambiguous) are exactly when the total time is worth knowing. Registered
   // after logf's Close, so it still has an open file to write to.
   defer func() {
      el := time.Since(start).Round(time.Millisecond)
      logMu.Lock()
      werr := logErr
      logMu.Unlock()
      w("elapsed " + el.String())
      if werr != nil {
         fmt.Fprintf(os.Stderr, "prkf -2: %s: %v (the log above is incomplete)\n",
            scanLogPath, werr)
      }
      fmt.Printf("elapsed %s\n", el)
   }()

   w("dll    " + dllPath)
   w("sha256 " + shaHex)
   w("size   " + strconv.Itoa(len(data)))
   w("start  " + start.Format("2006-01-02 15:04:05"))
   w("")

   _, secs := peSections(data)
   descs := signingCandidates(data, secs)
   w(fmt.Sprintf("heap descriptors: %d", len(descs)))
   fmt.Printf("heap descriptors: %d\n", len(descs))

   self, err := os.Executable()
   if err != nil {
      return err
   }
   w("self   " + self)

   // Probe every descriptor, eight at a time. Each probe is its own process
   // (see child.go), so the children share nothing and the parent only
   // collects stdout. Results are stored by descriptor index, so the log and
   // the ACCEPT lines below stay in descriptor order no matter which child
   // finishes first.
   results := make([]childOut, len(descs))

   type running struct {
      desc uint32
      t0   time.Time
   }

   var (
      mu       sync.Mutex
      done     int
      accepted int
      active   = make(map[int]running)
   )

   // The watchdog answers the question the progress line cannot: when nothing
   // finishes, is one child stuck or all of them, and for how long. It prints
   // the descriptors still in flight, never the parent's stacks - see the
   // diagnostics note at the top of the file.
   stopWatch := make(chan struct{})
   watchDone := make(chan struct{})
   go func() {
      defer close(watchDone)
      tk := time.NewTicker(5 * time.Second)
      defer tk.Stop()
      for {
         select {
         case <-stopWatch:
            return
         case <-tk.C:
            mu.Lock()
            d, n := done, len(active)
            snap := make([]string, 0, n)
            now := time.Now()
            for idx, r := range active {
               snap = append(snap, fmt.Sprintf("idx=%d desc=%#x running=%s",
                  idx, r.desc, now.Sub(r.t0).Round(time.Millisecond)))
            }
            mu.Unlock()

            if n == 0 {
               continue
            }
            sort.Strings(snap)

            head := fmt.Sprintf("watchdog: done=%d/%d inflight=%d", d, len(descs), n)
            w(head)
            fmt.Println(head)
            for _, s := range snap {
               w("  " + s)
               fmt.Println("  " + s)
            }
         }
      }
   }()

   // Eight workers: each child loads the DLL and makes three calls, so this
   // trades process-table pressure for wall clock. nw == 0 only when there is
   // nothing to scan, where zero workers is correct - the send loop below is
   // then empty, so nothing can block.
   nw := min(8, len(descs))

   jobs := make(chan int)
   var wg sync.WaitGroup
   wg.Add(nw)
   for i := 0; i < nw; i++ {
      go func() {
         defer wg.Done()
         for i := range jobs {
            desc := descs[i].descVA

            mu.Lock()
            active[i] = running{desc: desc, t0: time.Now()}
            mu.Unlock()

            w(fmt.Sprintf("job %d start desc=%#x", i, desc))

            res := runChild(self, i, desc, w)

            mu.Lock()
            delete(active, i)
            mu.Unlock()

            w(fmt.Sprintf("job %d end   desc=%#x elapsed=%s exit=%s",
               i, desc, res.elapsed.Round(time.Millisecond), res.exit))

            results[i] = res // distinct index per job: no shared write

            mu.Lock()
            done++
            if strings.Contains(res.line, " ACCEPT ") {
               accepted++
            }
            if done%100 == 0 || done == len(descs) {
               fmt.Printf("  %d/%d  accepted=%d\n", done, len(descs), accepted)
            }
            mu.Unlock()
         }
      }()
   }
   for i := range descs {
      jobs <- i
   }
   close(jobs)
   wg.Wait()

   // Stopped before the log is read, and waited for: the watchdog writes to
   // logf, and logf is closed by the deferred Close on return.
   close(stopWatch)
   <-watchDone

   var acc []imgDesc
   var slow []int
   for i, res := range results {
      w(res.line)
      if res.elapsed > time.Second {
         slow = append(slow, i)
      }
      if strings.Contains(res.line, " ACCEPT ") {
         acc = append(acc, descs[i])
         fmt.Println("ACCEPT " + res.line)
      }
   }

   w("")
   w(fmt.Sprintf("children slower than 1s: %d", len(slow)))
   for _, i := range slow {
      w(fmt.Sprintf("  idx=%d desc=%#x elapsed=%s exit=%s",
         i, descs[i].descVA, results[i].elapsed.Round(time.Millisecond), results[i].exit))
   }

   w("")
   w(fmt.Sprintf("accepted: %d", len(acc)))
   for _, d := range acc {
      w(fmt.Sprintf("  desc %#09x code %#09x+%#07x", d.descVA, d.rva, d.ln))
   }

   if len(acc) == 0 {
      return errors.New("no descriptor satisfied the signing-key routine's properties\n" +
         "  See the per-descriptor probe results in " + scanLogPath + "\n" +
         "  Either the hardcoded argument layout no longer matches this build,\n" +
         "  or this library does not contain the routine")
   }
   if len(acc) > 1 {
      return fmt.Errorf("%d descriptors satisfied every property - genuinely "+
         "ambiguous; investigate before trusting either", len(acc))
   }

   d := acc[0]
   rec := subRecord{
      SHA256:  shaHex,
      DescVA:  d.descVA,
      CodeRVA: d.rva,
      SegLen:  d.ln,
   }

   // One marshal: the cache is the same text the log and stdout carry.
   compact, err := json.Marshal(rec)
   if err != nil {
      return err
   }
   if err := os.WriteFile(prsubsPath, compact, 0o644); err != nil {
      return err
   }

   w("")
   w("cache: " + string(compact))
   fmt.Println("written " + scanLogPath)
   fmt.Println("written " + prsubsPath)
   fmt.Printf("cache: %s\n", compact)
   return nil
}

// ---- the kernel call -----------------------------------------------------

// decryptSigningKey decrypts a 32-byte obfuscated PlayReady signing key,
// reading the *.sig.prv component from prvPath and returning the 32-byte
// plaintext. Nothing is written; cmdDecrypt writes after validating.
func decryptSigningKey(prvPath string) ([]byte, error) {
   rec, err := loadPrsubs()
   if err != nil {
      return nil, err
   }

   // The module has to be mapped in this process before the call: rec.DescVA
   // is an RVA relative to its image base, not a file offset.
   base, err := loadWarbird()
   if err != nil {
      return nil, err
   }

   enc, err := os.ReadFile(prvPath)
   if err != nil {
      return nil, err
   }
   if len(enc) != keyLen {
      return nil, fmt.Errorf("%s: expected %d bytes, got %d", prvPath, keyLen, len(enc))
   }

   // A random fill proves the routine actually wrote to the output buffer;
   // a fixed sentinel could collide with real key material.
   fill := make([]byte, keyLen)
   if _, err := rand.Read(fill); err != nil {
      return nil, err
   }
   keyBuf := append(make([]byte, 0, keyLen), enc...) // the routine gets its own copy
   status := make([]byte, 0x10)                      // zero-filled
   out := append(make([]byte, 0, keyLen), fill...)

   // The block, the call and the lifetime handling are in warbird.go, so this
   // step and -2 cannot disagree about the ABI. out must stay live until the
   // result is read - its address is stored as a uintptr - and it is, by the
   // comparison below.
   args := newWbArgs(uint64(base)+uint64(rec.DescVA), status, keyBuf, out, keyLen)
   st := callWarbird(args)

   if st32 := uint32(st); st32 != 0 {
      msg := fmt.Sprintf("NtQuerySystemInformation -> %#010x", st32)
      if st32 == 0xC0000095 {
         msg += " (INTEGER_OVERFLOW: desc_va is wrong for this build)"
      }
      return nil, errors.New(msg)
   }

   if !statusOK(status) {
      return nil, fmt.Errorf("routine returned %s - the argument layout no "+
         "longer matches this build; re-run prkf -2",
         hex.EncodeToString(status[:4]))
   }

   if bytes.Equal(out, fill) {
      return nil, errors.New("output buffer untouched - out_off is wrong")
   }
   if bytes.Equal(out, enc) {
      return nil, errors.New("output equals input - desc_va is the wrong routine")
   }

   return out, nil
}

func isFile(p string) bool {
   fi, err := os.Stat(p)
   return err == nil && fi.Mode().IsRegular()
}

// spanMapped reports whether [rva, rva+n) lies inside one section's mapped
// extent, which is the larger of its virtual and raw sizes.
func spanMapped(secs []imgSection, rva, n uint32) bool {
   lo, hi := uint64(rva), uint64(rva)+uint64(n)
   for _, s := range secs {
      if uint64(s.va) <= lo && hi <= uint64(s.va)+uint64(max(s.vs, s.rs)) {
         return true
      }
   }
   return false
}

// ------------------------------------------------------------- descriptors

// signingCandidates is the shared census filtered to what -2 can probe: a
// heap-exec descriptor whose code span is non-empty and lies inside a mapped
// section.
//
// This is a filter, not a second scan. The digest validation, the section walk
// and the size cap are all scanDescs's, so -2 cannot drift from -5, -6 and -7
// about which bytes are a descriptor. The dedupe by (desc_va, code rva, len)
// stays because overlapping section extents can present the same descriptor
// twice, and probing it twice would waste a process and inflate the count.
func signingCandidates(fb []byte, secs []imgSection) []imgDesc {
   type key struct{ va, rva, ln uint32 }
   seen := make(map[key]bool)
   var out []imgDesc

   _, heaps := splitDescs(fb, secs)
   for _, d := range heaps {
      if d.ln == 0 || !spanMapped(secs, d.rva, d.ln) {
         continue
      }
      k := key{d.descVA, d.rva, d.ln}
      if seen[k] {
         continue
      }
      seen[k] = true
      out = append(out, d)
   }

   // A total order over keys the map already deduplicated: no equal elements
   // can reach the comparator, so stability would buy nothing.
   sort.Slice(out, func(i, j int) bool {
      a, b := out[i], out[j]
      if a.rva != b.rva {
         return a.rva < b.rva
      }
      if a.descVA != b.descVA {
         return a.descVA < b.descVA
      }
      return a.ln < b.ln
   })
   return out
}

// ---------------------------------------------------------------- the cache

// subRecord is prsubs.json: the one build-specific value the pipeline caches,
// plus the descriptor it came from, so the file records what -2 picked without
// anyone having to re-run it.
//
// -2 writes all four fields; -3 reads SHA256 and DescVA and ignores the other
// two, which is why there is one type here and not two. -3's validation is the
// SHA256 comparison: a cache written against another DLL is refused, not
// reinterpreted.
type subRecord struct {
   SHA256  string `json:"sha256"`
   DescVA  uint32 `json:"desc_va"`
   CodeRVA uint32 `json:"code_rva"`
   SegLen  uint32 `json:"seg_len"`
}

// loadPrsubs loads and validates the build-specific descriptor RVA.
func loadPrsubs() (*subRecord, error) {
   dll, err := os.ReadFile(dllPath)
   if err != nil {
      return nil, err
   }
   sum := sha256.Sum256(dll)
   sha := hex.EncodeToString(sum[:])

   if !isFile(prsubsPath) {
      return nil, fmt.Errorf("no %s - run prkf -2 first", prsubsPath)
   }
   raw, err := os.ReadFile(prsubsPath)
   if err != nil {
      return nil, err
   }
   var rec subRecord
   if err := json.Unmarshal(raw, &rec); err != nil {
      return nil, fmt.Errorf("%s: %v", prsubsPath, err)
   }

   if rec.SHA256 != sha {
      return nil, fmt.Errorf("%s was built for a different DLL\n"+
         "  cache : %s\n"+
         "  actual: %s\n"+
         "  re-run prkf -2", prsubsPath, rec.SHA256, sha)
   }
   if rec.DescVA == 0 {
      return nil, fmt.Errorf("%s has no desc_va - re-run prkf -2", prsubsPath)
   }
   return &rec, nil
}

// signing.go end
