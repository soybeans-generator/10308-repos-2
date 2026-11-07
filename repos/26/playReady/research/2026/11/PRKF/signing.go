// signing.go begin
//go:build windows

// prkf -2 and -3: find the signing-key routine's descriptor, then decrypt the
// signing key with it.
//
// One file, because the two steps are one branch: -2 writes prsubs.json and -3
// reads it, both call through the same ABI in warbird.go, and both name the
// same DLL. The producer and the consumer of a single 100-byte record do not
// belong in two files that cannot be read apart.
//
// ================================== -2 =======================================
//
// It scans the DLL for Warbird heap-exec descriptors, then re-executes this
// binary once per candidate, scanWorkers at a time, and reads the RESULT line
// each child prints. The child, the call it makes, and the argument block all
// live in warbird.go; this file owns the parent side of the scan.
//
// This step does NOT use sample key files. Discovery rests entirely on
// properties of the routine itself, read from its disassembly:
//
//  1. accepts exactly 0x20 bytes and succeeds
//     (the routine begins: cmp dword ptr [rcx+10h], 20h)
//  2. writes its output buffer
//     (it copies the input there, then transforms in place)
//  3. different input -> different output
//     (a key transform cannot ignore its input)
//  4. REJECTS a size other than 0x20
//     (property 1's converse; no generic routine enforces this)
//
// Property 4 is the discriminating one - it collapses the large set of
// descriptors that merely return success. Verification against a real key is
// -3's job, not -2's.
//
// The ONLY value that differs between DLL builds is the RVA of the heap
// descriptor holding the routine.
//
// A result of ZERO accepted descriptors, or more than one, is an error to
// investigate - there is no fallback path.
//
// Outputs: prsubsPath (build-specific values, keyed by the DLL sha256) and
// scanLogPath (per-descriptor probe results and every child's trace). Both are
// declared in main.go's manifest.
//
// # DIAGNOSTICS
//
// A scan that stalls has three possible shapes - one child spinning, several
// spinning, or the parent deadlocked - and from the progress line alone they
// look identical. The log distinguishes them:
//
//   job N start / job N end   one line per descriptor, with wall clock
//   trace[i desc] ...         the child's own phase trace, streamed live
//   watchdog ...              every 5s while work is in flight, names the
//                             descriptors still running and for how long
//
// A stuck descriptor therefore leaves its last trace line as the final record
// for that index: `probe B begin` means the child never returned from the
// kernel call for probe B. There is no deadline to cut the run short, so
// interrupt it and read the log.
//
// If the log shows work in flight but the watchdog lines never name a growing
// duration, the parent itself is stuck rather than a child. This file does not
// dump the parent's stacks: send the process Ctrl-Break and the Go runtime
// prints a goroutine dump by itself, which is the same evidence without an
// import of runtime here.
//
// NOTE: this file owns scanWorkers and the -2 scan. dllPath is in main.go's
// manifest; descTotal and the descriptor layout are in warbird.go; keyLen,
// warbirdOp, argsLen and probeEnv are the Warbird ABI and are also there, along
// with the probe child. -3 builds the same argument block rather than
// redeclaring it.
//
// ================================== -3 =======================================
//
// Decrypts a PlayReady signing key (sigPrvPath -> sigPlainPath).
//
// The names are fixed: input, output and public key are the ones -1 produces.
// The output is written only after every available check passes.
//
// # VERSION SUPPORT
//
// Only ONE value differs between DLL builds: the RVA of the heap descriptor
// holding the signing-key routine. It comes from prsubsPath, keyed by the DLL
// sha256 and produced by -2, which does not use sample keys. This step refuses
// to run if the cache does not match the DLL.
//
// Everything else is hardcoded because it cannot drift with the DLL:
//
//   - op=3 and the WarbirdCallArgs layout are a kernel ABI. The DLL and the
//     running kernel must agree on them, so neither can change unilaterally.
//     The block, the call and the module load are all in warbird.go, shared
//     with -2.
//   - The routine's own argument struct is packed (it reads its output pointer
//     unaligned at +0x14), and packed layout is fixed by source and invariant
//     under recompilation.
//   - size == 0x20 is the P-256 private scalar length, and the routine tests it
//     itself with `cmp dword ptr [rcx+10h], 20h`.
//
// Run -2 first; both steps agree on the directory because both go through
// main.go's manifest.
//
// # VERIFICATION
//
// The check is cryptographic and needs no secret reference: the plaintext d
// must satisfy d*G == Q, where Q is the P-256 public key that -1 wrote next to
// the ciphertext. A wrong descriptor, a wrong output offset, a wrong argument
// layout or a wrong input file cannot produce a scalar whose public point lands
// on Q. Cost: a few milliseconds.
//
// crypto/ecdh covers both directions: NewPublicKey rejects a published point
// that is off the curve or at infinity, and NewPrivateKey rejects a scalar
// outside [1, n-1] before the base-point multiply is reached. That range
// rejection is why no separate range test appears below.
//
// Failure is loud, never silent:
//
//   wrong desc_va     -> NTSTATUS 0xC0000095 (INTEGER_OVERFLOW)
//   wrong arg layout  -> status dword 0x80070057 (E_INVALIDARG) and an
//                        unwritten output buffer; -2 would also report zero
//                        accepted descriptors
//   output == input   -> descriptor for the wrong routine
//   d*G != sig.pub    -> descriptor, argument layout or input is wrong
//
// NOTE: keyLen, argsLen, statusOK, wbArgs, newWbArgs, loadWarbird and
// callWarbird are in warbird.go. This half imports neither unsafe nor syscall:
// the one pointer conversion and the one module load are both inside warbird.go.
package main

import (
   "bytes"
   "crypto/ecdh"
   "crypto/rand"
   "crypto/sha256"
   "debug/pe"
   "encoding/binary"
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

// How many probe subprocesses run at once. Each child loads the DLL and makes
// three calls, so this trades process-table pressure for wall clock; 8 keeps a
// typical machine busy without starving it.
const scanWorkers = 8

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

   f, err := pe.NewFile(bytes.NewReader(data))
   if err != nil {
      return fmt.Errorf("parse PE: %w", err)
   }
   defer f.Close()

   logf, err := os.Create(scanLogPath)
   if err != nil {
      return err
   }
   defer logf.Close()
   // *os.File writes are unbuffered, so each line reaches the log as soon as
   // it is written - useful when the scan dies partway through. logMu exists
   // because the workers and the watchdog both write.
   var logMu sync.Mutex
   w := func(s string) {
      logMu.Lock()
      fmt.Fprintln(logf, s)
      logMu.Unlock()
   }

   // Deferred, not printed inline: the error returns below (zero accepted,
   // ambiguous) are exactly when the total time is worth knowing. Registered
   // after logf's Close, so it still has an open file to write to.
   defer func() {
      el := time.Since(start).Round(time.Millisecond)
      w("elapsed " + el.String())
      fmt.Printf("elapsed %s\n", el)
   }()

   w("dll    " + dllPath)
   w("sha256 " + shaHex)
   w("size   " + strconv.Itoa(len(data)))
   w("start  " + start.Format("2006-01-02 15:04:05"))
   w("")

   descs := heapDescs(data, f.Sections)
   w(fmt.Sprintf("heap descriptors: %d", len(descs)))
   fmt.Printf("heap descriptors: %d\n", len(descs))

   self, err := os.Executable()
   if err != nil {
      return err
   }
   w("self   " + self)

   // Probe every descriptor, scanWorkers at a time. Each probe is its own
   // process (see warbird.go), so the children share nothing and the parent
   // only collects stdout. Results are stored by descriptor index, so the log
   // and the ACCEPT lines below stay in descriptor order no matter which child
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

   // nw == 0 only when there is nothing to scan, where zero workers is
   // correct: the send loop below is then empty, so nothing can block.
   nw := scanWorkers
   if nw > len(descs) {
      nw = len(descs)
   }

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

   var acc []descriptor
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
      w(fmt.Sprintf("  desc %#09x code %#09x+%#07x", d.descVA, d.codeRVA, d.codeLen))
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
      CodeRVA: d.codeRVA,
      SegLen:  d.codeLen,
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
   base, ntq, err := loadWarbird()
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
   st, _, _ := callWarbird(ntq, args)

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

// ------------------------------------------------------------- descriptors

type descriptor struct {
   descVA  uint32 // masked with 0x0FFFFFFF (top nibble is a flag)
   codeRVA uint32
   codeLen uint32
}

// heapDescs collects digest-validated Warbird heap-exec descriptors.
//
// This is the -2 scan, not the shared census in warbird.go: it needs the code
// span to lie inside a mapped section and it deduplicates by (desc_va, rva,
// len), which the other steps do not.
//
// Descriptor layout, relative to its base:
//
//   +0x00  32-byte SHA-256 over [0x20, 0xF0)
//   +0x20  u32 total size (0xF0)
//   +0x24  u32 v1 marker (0xFFFFFF00)
//   +0x28  u32 desc_va
//   +0x34  u32 encr_va   (0xF0000000 | code_rva)
//   +0x38  u32 size      (0xF0000000 | code_len)
//
// Only descriptors whose code segment lies entirely inside a mapped section
// are returned, sorted by code RVA.
func heapDescs(data []byte, secs []*pe.Section) []descriptor {
   // A section is mapped over the larger of its virtual and raw extents, so a
   // code span is rejected only when it lies outside both. Built once: it is
   // consulted for every candidate in every section.
   ranges := make([]rng, 0, len(secs))
   for _, s := range secs {
      extent := uint64(s.VirtualSize)
      if uint64(s.Size) > extent {
         extent = uint64(s.Size)
      }
      ranges = append(ranges, rng{uint64(s.VirtualAddress), uint64(s.VirtualAddress) + extent})
   }

   type key struct{ va, rva, ln uint32 }
   found := make(map[key]struct{})
   le := binary.LittleEndian

   for _, s := range secs {
      if s.Size < descTotal {
         continue
      }
      start := int(s.Offset)
      if start >= len(data) {
         continue
      }
      end := start + int(s.Size)
      if end > len(data) {
         end = len(data) // clamp to the bytes actually present
      }
      blob := data[start:end]

      for off := 0; off+descTotal <= len(blob); off += 4 {
         if le.Uint32(blob[off+0x20:]) != descTotal {
            continue
         }
         if le.Uint32(blob[off+0x24:]) != 0xFFFFFF00 {
            continue
         }
         body := blob[off+0x20 : off+descTotal]
         sum := sha256.Sum256(body)
         if !bytes.Equal(sum[:], blob[off:off+0x20]) {
            continue
         }
         descVA := le.Uint32(blob[off+0x28:])
         encrVA := le.Uint32(blob[off+0x34:])
         codeSz := le.Uint32(blob[off+0x38:])
         // top nibble of both fields is a flag; the rest is an RVA
         codeRVA := encrVA & 0x0FFFFFFF
         codeLen := codeSz & 0x0FFFFFFF
         if codeLen == 0 {
            continue
         }
         lo, hi := uint64(codeRVA), uint64(codeRVA)+uint64(codeLen)
         for _, r := range ranges {
            if r.lo <= lo && hi <= r.hi {
               found[key{descVA & 0x0FFFFFFF, codeRVA, codeLen}] = struct{}{}
               break
            }
         }
      }
   }

   out := make([]descriptor, 0, len(found))
   for k := range found {
      out = append(out, descriptor{descVA: k.va, codeRVA: k.rva, codeLen: k.ln})
   }
   // A total order over keys the map already deduplicated: no equal elements
   // can reach the comparator, so stability would buy nothing.
   sort.Slice(out, func(i, j int) bool {
      a, b := out[i], out[j]
      if a.codeRVA != b.codeRVA {
         return a.codeRVA < b.codeRVA
      }
      if a.descVA != b.descVA {
         return a.descVA < b.descVA
      }
      return a.codeLen < b.codeLen
   })
   return out
}

// rng is one mapped section's address extent.
type rng struct{ lo, hi uint64 }

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
