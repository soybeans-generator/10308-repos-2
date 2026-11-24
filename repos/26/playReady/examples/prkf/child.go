// child.go begin
//go:build windows

// The process plumbing every step shares: the child spec, the spawn, and the one grammar.
//
// A CHILD IS IDENTIFIED BY ITS ENVIRONMENT, NOT ITS ARGUMENTS: one variable, one JSON
// childSpec, decoded and validated once in childMode. No child mode appears in `prkf -h`
// and every child has an empty command line.
//
// WHY A CHILD IS A SEPARATE PROCESS: a fault in a descriptor's code is a Windows SEH
// exception raised inside the DLL, not a Go panic. recover() never runs and the process
// dies, so one child per candidate confines a fault to that candidate.
//
// THE ROWS ARE THE WHOLE REPORT. Every child prints childRow, one JSON object per line, and
// closes with k=end. Whether it finished is read from that end row, never from its exit
// status: no end row means it died in native code or was killed, and the rows before it say
// where. The only nonzero exit is main's 2 for a malformed payload - a spawn bug, whose
// message is on stderr.
package main

import (
   "bufio"
   "bytes"
   "encoding/hex"
   "encoding/json"
   "fmt"
   "io"
   "os"
   "os/exec"
   "time"
)

// childEnv is the one variable a child is identified by: its value is a JSON childSpec.
const childEnv = "PRKF_CHILD"

// childEnc is the one writer. Encode appends the newline, and an *os.File write is a
// syscall, so a row is out of the child before the next statement - including when the next
// statement is the call that never returns.
var childEnc = json.NewEncoder(os.Stdout)

// selfPath and selfErr are resolved once at init: four drivers spawn children of themselves.
var selfPath, selfErr = os.Executable()

// childEnvFor renders spec as the one NAME=VALUE entry a spawn site passes.
func childEnvFor(spec *childSpec) (string, error) {
   b, err := json.Marshal(spec)
   if err != nil {
      return "", fmt.Errorf("%s: %w", childEnv, err)
   }
   return childEnv + "=" + string(b), nil
}

// childMode reports whether this process is a re-executed child, and runs it if so. Called
// from main before the FlagSet exists: a child passes no arguments.
//
// It is the ONLY place a payload is validated. Each mode names exactly the fields it needs,
// so a malformed spec fails here with one message rather than in whichever worker tripped
// over it. A worker's verdicts are rows, never a return code.
func childMode() (ok bool, err error) {
   s := os.Getenv(childEnv)
   if s == "" {
      return false, nil
   }

   var spec childSpec
   if err := json.Unmarshal([]byte(s), &spec); err != nil {
      return true, fmt.Errorf("%s: %w", childEnv, err)
   }

   switch spec.Mode {
   case "probe":
      if len(spec.Descs) == 0 {
         return true, fmt.Errorf("%s: probe with no descriptors", childEnv)
      }
      runProbes(spec.Descs)

   case "sweep":
      // One descriptor, because a sweep drives one consumer. Families are indices into
      // dmFams, so the range is checked against it and not against a literal.
      if len(spec.Descs) != 1 {
         return true, fmt.Errorf("%s: sweep needs exactly one descriptor, got %d",
            childEnv, len(spec.Descs))
      }
      if len(spec.Fams) == 0 || len(spec.Sets) == 0 {
         return true, fmt.Errorf("%s: sweep needs families and sets", childEnv)
      }
      for _, f := range spec.Fams {
         if f < 0 || f >= len(dmFams) {
            return true, fmt.Errorf("%s: family %d is not one of %d", childEnv, f, len(dmFams))
         }
      }
      dmWorker(spec.Descs[0], spec.Fams, spec.Sets)

   case "p1":
      // Phase 1 is phase 2 with one empty OBF, and the empty value is what selects the
      // phase-1 argument shape, so exactly one is required and it must be empty.
      if len(spec.Descs) == 0 {
         return true, fmt.Errorf("%s: p1 with no descriptors", childEnv)
      }
      if len(spec.Obfs) != 1 || spec.Obfs[0] != "" {
         return true, fmt.Errorf("%s: p1 needs exactly one empty OBF slot, got %d",
            childEnv, len(spec.Obfs))
      }
      dpWorker(spec.Mode, 0, spec.Obfs, spec.Descs)

   case "p2":
      // One OBF per candidate: the worker indexes obfs[oi] for every triple.
      if len(spec.Descs) == 0 || len(spec.Obfs) == 0 {
         return true, fmt.Errorf("%s: p2 needs descriptors and OBFs", childEnv)
      }
      if spec.Start < 0 {
         return true, fmt.Errorf("%s: p2 start %d is negative", childEnv, spec.Start)
      }
      dpWorker(spec.Mode, spec.Start, spec.Obfs, spec.Descs)

   default:
      return true, fmt.Errorf("%s: unknown mode %q", childEnv, spec.Mode)
   }
   return true, nil
}

// emit prints one row. The only error Encode can return here is a write to a closed pipe,
// which the parent already reports as a missing end row.
func emit(r childRow) { _ = childEnc.Encode(r) }

// endedRow reports whether the last non-blank line of stdout is a k=end row. It parses one
// line and not the stream, because readRows belongs to the callers that want the rows. A
// child killed mid-write leaves a truncated final line, which is not an end row: correct.
func endedRow(stdout []byte) bool {
   lines := bytes.Split(stdout, []byte("\n"))
   for i := len(lines) - 1; i >= 0; i-- {
      ln := bytes.TrimSpace(lines[i])
      if len(ln) == 0 {
         continue
      }
      var r childRow
      return json.Unmarshal(ln, &r) == nil && r.Kind == "end"
   }
   return false
}

// isHex reports whether s decodes as hex bytes.
func isHex(s string) bool {
   _, err := hex.DecodeString(s)
   return err == nil
}

// isHex32 reports whether s is exactly 0x20 bytes of hex. Length alone is not the test:
// hex.DecodeString returns the bytes it did decode alongside its error.
func isHex32(s string) bool { return len(s) == 0x40 && isHex(s) }

// childRow is one line a child prints, and the only thing a parent parses.
//
//   k=ok        p1/p2  d descriptor, i OBF, h key half, b key buffer then output buffer
//   k=reject    p1/p2  d, i, h, s the status dword
//   k=accept    probe  d, b[0] A output, b[1] B output, s A/B/C status, e the verdict detail
//   k=none      probe  d, e why no verdict was reached
//   k=meta      sweep  e one human log line
//   k=live      sweep  f family, i set index, d the live set rva
//   k=nolive    sweep  f family, i how many sets were live
//   k=out       sweep  f family, i licence, h forced nibble, s status, b[0] value
//   k=fault     any    e the FAULT detail, emitted by wbVEH just before it exits
//   k=err       any    e why the child could not start or run - never a property of a
//                      candidate, so it aborts the batch instead of being skipped
//   k=loadfail  any    e why the module could not be patched
//   k=end       any    last row; its absence means the child died in native code
type childRow struct {
   Kind string   `json:"k"`
   Desc uint32   `json:"d,omitempty"`
   Fam  int      `json:"f,omitempty"`
   Idx  int      `json:"i,omitempty"`
   Half int      `json:"h,omitempty"`
   Buf  []string `json:"b,omitempty"`
   St   []string `json:"s,omitempty"`
   Msg  string   `json:"e,omitempty"`
}

// readRows parses a child's stdout. Blank lines are skipped, and every b and s entry must be
// hex: every caller decodes those fields without a second look, so a malformed one is a
// parse failure here rather than a silent "no match" ten steps later.
//
// A final line that does not parse is dropped, not fatal: it has no trailing newline, so it
// is a row a killed child was still writing.
func readRows(stdout []byte) ([]childRow, error) {
   lines := bytes.Split(stdout, []byte("\n"))
   var out []childRow
   for i, ln := range lines {
      if len(bytes.TrimSpace(ln)) == 0 {
         continue
      }
      var r childRow
      if err := json.Unmarshal(ln, &r); err != nil {
         if i == len(lines)-1 {
            break
         }
         return nil, fmt.Errorf("child row %q: %w", ln, err)
      }
      if r.Kind == "" {
         return nil, fmt.Errorf("child row %q: no kind", ln)
      }
      for _, f := range append(r.Buf, r.St...) {
         if !isHex(f) {
            return nil, fmt.Errorf("child row %q: %q is not hex", ln, f)
         }
      }
      out = append(out, r)
   }
   return out, nil
}

// log renders a row for a step's log file.
func (r childRow) log() string {
   b, _ := json.Marshal(r)
   return string(b)
}

// childSpec is a child's whole payload. Descs is descriptor VAs for "probe", "p1" and "p2",
// and the single consumer descRVA for "sweep". Obfs is a single "" for "p1", where the empty
// value selects the phase-1 argument shape, and the full list for "p2".
type childSpec struct {
   Mode  string   `json:"mode"`            // probe | sweep | p1 | p2
   Descs []uint32 `json:"descs,omitempty"` // probe, p1, p2; sweep uses the one element
   Fams  []int    `json:"fams,omitempty"`  // sweep
   Sets  []uint32 `json:"sets,omitempty"`  // sweep
   Obfs  []string `json:"obfs,omitempty"`  // p1, p2
   Start int      `json:"start,omitempty"` // p2
}

// ------------------------------------------------------------ spawn helpers

// procOut is one collected child run. ended is the completion signal: the last row was
// k=end. err is non-nil only when the process could not be started or the spec could not be
// encoded.
type procOut struct {
   stdout []byte
   ended  bool
   err    error
}

// runCollect spawns this binary as a child and returns its stdout. The child is identified by
// env alone and passed no arguments; spec is encoded here, so no caller formats a payload and
// no child re-parses a hand-built string.
//
// timeout > 0 bounds the run; -1's probe passes 0, because a deadline there would make a hang
// indistinguishable from a fault. A child killed on the deadline simply has no end row, so
// the timer is never consulted. stream, when non-nil, receives each stderr line as it arrives
// and before Wait, so a child that never exits still leaves its trace.
func runCollect(spec *childSpec, timeout time.Duration, stream func(string)) *procOut {
   if selfErr != nil {
      return &procOut{err: selfErr}
   }
   entry, err := childEnvFor(spec)
   if err != nil {
      return &procOut{err: err}
   }

   cmd := exec.Command(selfPath)
   // Last value wins: exec dedupes Env case-insensitively on Windows, so an inherited
   // PRKF_CHILD is shadowed by this spawn's spec rather than needing to be removed.
   cmd.Env = append(os.Environ(), entry)
   var so bytes.Buffer
   cmd.Stdout = &so

   var er io.ReadCloser
   if stream != nil {
      if er, err = cmd.StderrPipe(); err != nil {
         return &procOut{err: err}
      }
   }
   if err := cmd.Start(); err != nil {
      return &procOut{err: err}
   }

   // Armed after Start because the callback dereferences cmd.Process, which is nil until
   // then. Stop only releases the timer; a Kill that fails means the child already exited.
   if timeout > 0 {
      defer time.AfterFunc(timeout, func() { _ = cmd.Process.Kill() }).Stop()
   }

   if er != nil {
      sc := bufio.NewScanner(er)
      sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
      for sc.Scan() {
         stream("  " + sc.Text())
      }
      // The scanner's error is the only signal that the trace ended early: dropped, a
      // truncated trace would be indistinguishable from a complete one.
      if serr := sc.Err(); serr != nil {
         stream(fmt.Sprintf("  TRACE TRUNCATED: %v", serr))
      }
   }

   // Reading stderr to EOF before Wait is the documented pattern: Wait closes the pipe, so
   // every trace line is out of the child before the rows are read. The exit status is
   // discarded: the rows carry the verdicts and the end row carries completion.
   _ = cmd.Wait()

   return &procOut{stdout: so.Bytes(), ended: endedRow(so.Bytes())}
}

// child.go end
