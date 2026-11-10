// signing.go begin
//go:build windows

// prkf -1 and -5: find the signing-key routine's descriptor, then decrypt the signing key
// with it. One file, because -1 writes prsubs.json and -5 reads it, both call the same ABI
// in kernel.go, and both name the same DLL.
//
// -1 scans the DLL for Warbird heap-exec descriptors, then re-executes this binary once per
// CHUNK of candidates and reads the RESULT line each descriptor produced. Discovery rests
// entirely on properties of the routine itself, read from its disassembly - no sample key
// files:
//
//  1. accepts exactly 0x20 bytes and succeeds (cmp dword ptr [rcx+10h], 20h)
//  2. writes its output buffer; 3. different input -> different output
//  4. REJECTS a size other than 0x20
//
// Property 4 is the discriminating one - it collapses the large set of descriptors that
// merely return success. Verification against a real key is -5's job. Zero accepted
// descriptors, or more than one, is an error to investigate.
//
// Descriptors are probed in chunks of 64, sequentially: a child pays LoadLibrary before its
// first call, so one child per descriptor spent 981 module loads on 981 probes. A chunk
// that dies takes its remaining descriptors with it; a child prints its rows in order, so
// the first descriptor with no RESULT line is the one that faulted, and the rest are
// retried as a run. Every child streams its stderr into the log as it arrives, so a hung
// chunk leaves its last trace line as the final record - there is no deadline, because a
// timeout would make a hang invisible.
//
// Only ONE value differs between DLL builds: the RVA of the heap descriptor holding the
// signing-key routine, from prsubsPath keyed by the DLL sha256. This step refuses to run if
// the cache does not match. Everything else cannot drift: op=3 and the WarbirdCallArgs
// layout are kernel ABI; the routine's argument struct is packed and its layout fixed by
// source; size == 0x20 it tests itself.
package main

import (
   "bytes"
   "cmp"
   "crypto/rand"
   "encoding/hex"
   "encoding/json"
   "errors"
   "fmt"
   "os"
   "slices"
   "strconv"
   "strings"
   "time"
)

// probeChunk is how many descriptors one probe child handles.
const probeChunk = 64

// childT0 captures the process start, so every trace line can carry a millisecond offset.
var childT0 = time.Now()

// ------------------------------------------------------------ -5: decrypt

func cmdDecrypt() error {
   if !isFile(sigPrvPath) {
      return fmt.Errorf("missing input: %s\n  run prkf -4 first", sigPrvPath)
   }
   if !isFile(sigPubPath) {
      return fmt.Errorf("missing public key: %s\n  run prkf -4 first", sigPubPath)
   }

   got, err := decryptSigningKey(sigPrvPath)
   if err != nil {
      return err
   }
   fmt.Printf("%s (%d bytes)\n", sigPrvPath, len(got))
   fmt.Printf("plaintext %s\n", hex.EncodeToString(got))

   raw, err := os.ReadFile(sigPubPath)
   if err != nil {
      return err
   }
   // An out-of-range d makes pubFor return nil, which pubMatches reports as a mismatch.
   if !pubMatches(got, raw) {
      return fmt.Errorf("d*G != %s - the plaintext is not the private key for\n"+
         "that public key; the descriptor, the argument layout or the\n"+
         "input file is wrong; nothing was written", sigPubPath)
   }
   want := pubBytes(raw)
   fmt.Printf("[ OK ] d*G == %s\n", sigPubPath)
   fmt.Printf("       Q = (%s,\n            %s)\n",
      hex.EncodeToString(want[1:33]), hex.EncodeToString(want[33:65]))

   if err := os.WriteFile(sigPlainPath, got, 0o666); err != nil {
      return err
   }
   fmt.Printf("\nwrote %s (%d bytes)\n", sigPlainPath, len(got))
   return nil
}

// cmdFindSub is the entry point for prkf -1.
func cmdFindSub() error {
   start := time.Now() // taken before the DLL is read, so the total covers the step

   data, shaHex, err := pfDLL()
   if err != nil {
      return err
   }

   logf, err := os.Create(scanLogPath)
   if err != nil {
      return err
   }

   // Writes go straight to the file, not through stepLog: this log is the only evidence a
   // stalled scan leaves behind, so a line must be on disk before the next statement runs.
   // *os.File writes are unbuffered, which is exactly that guarantee. logErr keeps the
   // first write failure, because a log that stops mid-scan is worse than one that says so.
   var logErr error
   w := func(s string) {
      if logErr != nil {
         return
      }
      if _, err := fmt.Fprintln(logf, s); err != nil {
         logErr = err
      }
   }
   wf := func(f string, a ...any) { w(fmt.Sprintf(f, a...)) }

   // One defer, so the elapsed line - which is exactly what the error returns below are
   // worth knowing for - cannot run before the close is checked or after it is skipped.
   defer func() {
      w("elapsed " + time.Since(start).Round(time.Millisecond).String())
      switch cerr := logf.Close(); {
      case logErr != nil:
         fmt.Fprintf(os.Stderr, "prkf -1: %s: %v (the log above is incomplete)\n",
            scanLogPath, logErr)
      case cerr != nil:
         fmt.Fprintf(os.Stderr, "prkf -1: %s: close: %v\n", scanLogPath, cerr)
      }
   }()

   w("dll    " + dllPath)
   w("sha256 " + shaHex)
   w("size   " + strconv.Itoa(len(data)))
   w("start  " + start.Format("2006-01-02 15:04:05"))
   w("")

   _, secs := peSections(data)
   descs := signingCandidates(data, secs)
   wf("heap descriptors: %d", len(descs))
   fmt.Printf("heap descriptors: %d\n", len(descs))

   if selfErr != nil {
      return selfErr
   }
   w("self   " + selfPath)

   // One RESULT line per descriptor, keyed by descriptor VA. A descriptor with no line
   // either faulted its chunk or was never reached; the passes below recover both.
   results := make([]string, len(descs))
   chunks := (len(descs) + probeChunk - 1) / probeChunk
   wf("probing %d descriptors in %d chunks of %d", len(descs), chunks, probeChunk)

   tally := func() (done, accepted int) {
      for _, r := range results {
         if r != "" {
            done++
         }
         if strings.Contains(r, " ACCEPT ") {
            accepted++
         }
      }
      return
   }

   for lo := 0; lo < len(descs); lo += probeChunk {
      hi := min(lo+probeChunk, len(descs))
      wf("chunk %d/%d  idx %d..%d", lo/probeChunk+1, chunks, lo, hi-1)
      got := probeBatch(descs[lo:hi], w)
      for i := lo; i < hi; i++ {
         if r, ok := got[descs[i].descVA]; ok {
            results[i] = r
         }
      }
      done, accepted := tally()
      fmt.Printf("  %d/%d  accepted=%d\n", done, len(descs), accepted)
   }

   // A dead run is retried as a run: the faulting descriptor is recorded and skipped, and
   // everything behind it goes into the next pass. Recording NO_OUTPUT for the faulting
   // descriptor is what guarantees the next pass is strictly smaller - a routine that dies
   // on its first call is not the signing-key routine, so this is its verdict, not a gap.
   for pass := 0; ; pass++ {
      var missing []int
      for i, r := range results {
         if r == "" {
            missing = append(missing, i)
         }
      }
      if len(missing) == 0 {
         break
      }
      if pass == 0 {
         wf("retrying %d descriptors in chunks of %d", len(missing), probeChunk)
         fmt.Printf("  %d descriptors produced no row - retrying in chunks\n", len(missing))
      }

      for lo := 0; lo < len(missing); lo += probeChunk {
         run := missing[lo:min(lo+probeChunk, len(missing))]
         batch := make([]imgDesc, len(run))
         for j, i := range run {
            batch[j] = descs[i]
         }
         got := probeBatch(batch, w)

         for _, i := range run {
            if r, ok := got[descs[i].descVA]; ok {
               results[i] = r
               continue
            }
            results[i] = fmt.Sprintf("RESULT %#x NO_OUTPUT exit=no-row", descs[i].descVA)
            break
         }
      }

      done, accepted := tally()
      fmt.Printf("  pass %d  %d/%d  accepted=%d\n", pass+1, done, len(descs), accepted)
   }

   var acc []imgDesc
   for i, r := range results {
      w(r)
      if strings.Contains(r, " ACCEPT ") {
         acc = append(acc, descs[i])
         fmt.Println("ACCEPT " + r)
      }
   }

   w("")
   wf("accepted: %d", len(acc))
   for _, d := range acc {
      wf("  desc %#09x code %#09x+%#07x", d.descVA, d.rva, d.ln)
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
   compact, err := json.Marshal(subRecord{
      SHA256:  shaHex,
      DescVA:  d.descVA,
      CodeRVA: d.rva,
      SegLen:  d.ln,
   })
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

// decryptSigningKey decrypts a 32-byte obfuscated PlayReady signing key, reading the
// *.sig.prv component from prvPath and returning the 32-byte plaintext. Nothing is written;
// cmdDecrypt writes after validating.
func decryptSigningKey(prvPath string) ([]byte, error) {
   rec, err := loadPrsubs()
   if err != nil {
      return nil, err
   }

   // The module has to be mapped in this process before the call: rec.DescVA is an RVA
   // relative to its image base, not a file offset.
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

   // A random fill proves the routine actually wrote to the output buffer; a fixed sentinel
   // could collide with real key material.
   fill := make([]byte, keyLen)
   if _, err := rand.Read(fill); err != nil {
      return nil, err
   }
   keyBuf := slices.Clone(enc)  // the routine gets its own copy
   status := make([]byte, 0x10) // zero-filled
   out := slices.Clone(fill)

   st := op3Call(base)(rec.DescVA, 0x34, keyLen, status, keyBuf, out, nil)

   if st != 0 {
      msg := fmt.Sprintf("NtQuerySystemInformation -> %#010x", st)
      if st == 0xC0000095 {
         msg += " (INTEGER_OVERFLOW: desc_va is wrong for this build)"
      }
      return nil, errors.New(msg)
   }

   if !statusOK(status) {
      return nil, fmt.Errorf("routine returned %s - the argument layout no "+
         "longer matches this build; re-run prkf -1",
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

// runOne probes one descriptor and prints its RESULT line. A probe that cannot be set up
// still prints a line, because the parent would otherwise retry this descriptor forever.
func runOne(op3 op3Func, descVA uint32) {
   trace("probe %#x begin", descVA)

   // A and B differ, so a transform and a copy are distinguishable. C is A one byte short
   // and must be rejected: that property is what collapses the descriptors that merely
   // return success.
   inputA := make([]byte, keyLen)
   inputB := make([]byte, keyLen)
   for i := range inputA {
      inputA[i], inputB[i] = byte(i), byte(keyLen+i)
   }

   var p [3]*probeResult
   for i, c := range [3]struct {
      tag  string
      data []byte
      size uint32
   }{
      {"A", inputA, keyLen},
      {"B", inputB, keyLen},
      {"C", inputA, keyLen - 1},
   } {
      var err error
      if p[i], err = probe(op3, descVA, c.tag, c.data, c.size); err != nil {
         trace("probe %s failed: %v", c.tag, err)
         fmt.Printf("RESULT %#x NO_OUTPUT exit=setup:%v\n", descVA, err)
         return
      }
   }
   a, b, c := p[0], p[1], p[2]

   // Rejection is judged on NTSTATUS and the status dword alone - the output buffer is not
   // consulted, because a routine that refused the size wrote nothing to judge.
   okReject := !(c.ntstatus == 0 && statusOK(c.status))

   verdict := "REJECT"
   if a.wrote && b.wrote && !bytes.Equal(a.out, b.out) && okReject {
      verdict = "ACCEPT"
   }
   trace("emit %#x verdict=%s", descVA, verdict)

   fmt.Printf("RESULT %#x %s "+
      "A(st=%#010x,sv=%s) "+
      "B(st=%#010x,sv=%s) "+
      "C(st=%#010x,sv=%s) "+
      "input_dep=%t size_enforced=%t out=%s\n",
      descVA, verdict,
      a.ntstatus, hex.EncodeToString(a.status),
      b.ntstatus, hex.EncodeToString(b.status),
      c.ntstatus, hex.EncodeToString(c.status),
      !bytes.Equal(a.out, b.out), okReject,
      hex.EncodeToString(a.out))
}

// ------------------------------------------------------------ the -1 probe

// runProbes is the probe child's whole body: one module load, then three calls per
// descriptor.
func runProbes(descs []uint32) int {
   trace("start descriptors=%d keyLen=%#x", len(descs), keyLen)

   base, err := loadWarbird()
   if err != nil {
      trace("loadWarbird failed: %v", err)
      fmt.Fprintf(os.Stderr, "prkf: %v\n", err)
      return 2
   }
   trace("dll loaded base=%#x", base)

   op3 := op3Call(base)
   for _, d := range descs {
      runOne(op3, d)
   }
   trace("done")
   return 0
}

// spanMapped reports whether [rva, rva+n) lies inside one section's mapped extent, which is
// the larger of its virtual and raw sizes.
func spanMapped(secs []imgSection, rva, n uint32) bool {
   lo, hi := uint64(rva), uint64(rva)+uint64(n)
   for _, s := range secs {
      if uint64(s.va) <= lo && hi <= uint64(s.va)+uint64(max(s.vs, s.rs)) {
         return true
      }
   }
   return false
}

// trace writes one timestamped line to the child's stderr. Writes to stderr are unbuffered
// syscalls, so the line is out of this process before the next statement runs - including
// when the next statement is the kernel call that never returns.
func trace(format string, a ...any) {
   fmt.Fprintf(os.Stderr, "[pid %d +%dms] %s\n",
      os.Getpid(), time.Since(childT0).Milliseconds(), fmt.Sprintf(format, a...))
}

// ------------------------------------------------------------- descriptors

// signingCandidates is the shared census filtered to what -1 can probe: a heap-exec
// descriptor whose code span is non-empty and lies inside a mapped section.
//
// This is a filter, not a second scan: the digest validation, the section walk and the size
// cap are all scanDescs's. The dedupe by (desc_va, code rva, len) stays because overlapping
// section extents can present the same descriptor twice.
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

   // A total order over keys the map already deduplicated: no equal elements can reach the
   // comparator. rva first, so the order matches the code layout the log reports.
   slices.SortFunc(out, func(a, b imgDesc) int {
      if c := cmp.Compare(a.rva, b.rva); c != 0 {
         return c
      }
      if c := cmp.Compare(a.descVA, b.descVA); c != 0 {
         return c
      }
      return cmp.Compare(a.ln, b.ln)
   })
   return out
}

// probeResult is one WB heap-exec call. wrote is NTSTATUS 0, a zero status dword, and an
// output buffer that is neither the random fill nor the input - the whole success test, so
// no caller has to hold the fill or the input to decide it.
type probeResult struct {
   ntstatus uint32
   status   []byte // the 4 status bytes the routine wrote
   out      []byte
   wrote    bool
}

// probe performs one WB heap-exec call. A failure to draw the random fill is returned
// rather than exited on, so the caller decides what to print.
func probe(op3 op3Func, descVA uint32, tag string, data []byte, size uint32) (*probeResult, error) {
   trace("probe %#x %s begin size=%#x", descVA, tag, size)

   fill := make([]byte, keyLen)
   if _, err := rand.Read(fill); err != nil {
      return nil, fmt.Errorf("probe %s: random fill: %w", tag, err)
   }
   keyBuf := make([]byte, keyLen)
   copy(keyBuf, data) // always keyLen bytes; a short data leaves the tail zero
   status := make([]byte, 0x10)
   out := slices.Clone(fill)

   r1 := op3(descVA, 0x34, size, status, keyBuf, out, nil)
   trace("probe %#x %s returned st=%#010x sv=%x", descVA, tag, r1, status[:4])

   return &probeResult{
      ntstatus: r1,
      status:   status[:4], // per-call buffer, never reused, so no copy
      out:      out,
      wrote: r1 == 0 && statusOK(status) &&
         !bytes.Equal(out, fill) && !bytes.Equal(out, keyBuf),
   }, nil
}

// ---------------------------------------------------------------- the cache

// subRecord is prsubs.json: the one build-specific value the pipeline caches, plus the
// descriptor it came from. -5's validation is the SHA256 comparison: a cache written
// against another DLL is refused, not reinterpreted.
type subRecord struct {
   SHA256  string `json:"sha256"`
   DescVA  uint32 `json:"desc_va"`
   CodeRVA uint32 `json:"code_rva"`
   SegLen  uint32 `json:"seg_len"`
}

// loadPrsubs loads and validates the build-specific descriptor RVA.
func loadPrsubs() (*subRecord, error) {
   _, sha, err := pfDLL()
   if err != nil {
      return nil, err
   }

   if !isFile(prsubsPath) {
      return nil, fmt.Errorf("no %s - run prkf -1 first", prsubsPath)
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
         "  re-run prkf -1", prsubsPath, rec.SHA256, sha)
   }
   if rec.DescVA == 0 {
      return nil, fmt.Errorf("%s has no desc_va - re-run prkf -1", prsubsPath)
   }
   return &rec, nil
}

// signing.go end
