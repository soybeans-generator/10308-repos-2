// findsub.go begin
//go:build windows

// findsub.go is prkf -2: find the signing-key routine's descriptor.
//
// It scans the DLL for Warbird heap-exec descriptors, then re-executes this
// binary once per candidate, scanWorkers at a time, and reads the RESULT line
// each child prints. The child, the call it makes, and the argument block all
// live in warbird.go; this file owns the DLL, the descriptor layout, and the
// parent side of the scan.
//
// This program does NOT use sample key files. Discovery rests entirely on
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
// prkf -3's job, not this program's.
//
// The ONLY value that differs between DLL builds is the RVA of the heap
// descriptor holding the routine.
//
// A result of ZERO accepted descriptors, or more than one, is an error to
// investigate - there is no fallback path.
//
// Outputs, both in testdata/:
//
//   prsubs.json     build-specific values, keyed by the DLL sha256
//   findprsub.txt   per-descriptor probe results and every child's trace
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
// NOTE: this file owns dllPath, descTotal and scanWorkers. keyLen, warbirdOp,
// argsLen and probeEnv are the Warbird ABI and live in warbird.go, which also
// holds the probe child; prkf -3 builds the same argument block rather than
// redeclaring it.
package main

import (
   "bytes"
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

const (
   dllPath = `C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll`

   // Size of one Warbird heap-exec descriptor, including its 32-byte digest.
   // The descriptor's own size field holds this same value, which is what
   // makes it usable as a signature.
   descTotal = 0xF0

   // How many probe subprocesses run at once. Each child loads the DLL and
   // makes three calls, so this trades process-table pressure for wall clock;
   // 8 keeps a typical machine busy without starving it.
   scanWorkers = 8
)

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

   logPath := outFile("findprsub.txt")
   logf, err := os.Create(logPath)
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
         "  See the per-descriptor probe results in " + logPath + "\n" +
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
   cachePath := outFile("prsubs.json")
   if err := os.WriteFile(cachePath, compact, 0o644); err != nil {
      return err
   }

   w("")
   w("cache: " + string(compact))
   fmt.Println("written " + logPath)
   fmt.Println("written " + cachePath)
   fmt.Printf("cache: %s\n", compact)
   return nil
}

// ------------------------------------------------------------- descriptors

type descriptor struct {
   descVA  uint32 // masked with 0x0FFFFFFF (top nibble is a flag)
   codeRVA uint32
   codeLen uint32
}

// rng is one mapped section's address extent.
type rng struct{ lo, hi uint64 }

// heapDescs collects digest-validated Warbird heap-exec descriptors.
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

// ---------------------------------------------------------------- the cache

type subRecord struct {
   SHA256  string `json:"sha256"`
   DescVA  uint32 `json:"desc_va"`
   CodeRVA uint32 `json:"code_rva"`
   SegLen  uint32 `json:"seg_len"`
}

// findsub.go end
