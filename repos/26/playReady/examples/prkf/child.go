// child.go begin
//go:build windows

// The process plumbing every step shares: how a child is identified, how it is spawned, and
// the one grammar it speaks. No child BODY lives here - the probe child is in signing.go,
// the sweep and trial children in trials.go, and this file is what they agree on.
//
// A CHILD IS IDENTIFIED BY ITS ENVIRONMENT, NOT BY ITS ARGUMENTS: one variable, one JSON
// childSpec, decoded and validated once in childMode. No child mode appears in `prkf -h`
// and every step has an empty command line.
//
// WHY A CHILD IS A SEPARATE PROCESS: a fault in a descriptor's code is a Windows SEH
// exception raised inside the DLL, not a Go panic. recover() never runs and the whole
// process dies, so one child per candidate confines a fault to that candidate.
//
// THE WIRE IS ONE GRAMMAR. Every child prints childRow, one JSON object per line, and
// closes with k=end. A caller knows which mode it spawned, so no row names it. A child with
// no end row died inside native code, and the rows before it say where - so no caller
// matches on prose, and no caller re-derives an index the child already knew.
//
// EXIT CODES: nothing here calls os.Exit. 0 after the rows, 2 for a bad payload, 4 when
// the module cannot be loaded, 5 on bad input or a recovered panic, 6 when no fault
// handler could be installed.
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

// childEnv is the one variable a child is identified by. Its value is a JSON childSpec;
// nothing else about the process differs from its parent.
const childEnv = "PRKF_CHILD"

// childEnc is the one writer. Encode appends the newline, and an *os.File write is a
// syscall, so a row is out of the child before the next statement - including when the next
// statement is the call that never returns.
var childEnc = json.NewEncoder(os.Stdout)

// ------------------------------------------------------------- the payload

// selfPath and selfErr are resolved once at init: four drivers spawn children of
// themselves and each needs the same answer.
var selfPath, selfErr = os.Executable()

// childEnvFor renders spec as the one NAME=VALUE entry a spawn site passes.
func childEnvFor(spec *childSpec) (string, error) {
   b, err := json.Marshal(spec)
   if err != nil {
      return "", fmt.Errorf("%s: %w", childEnv, err)
   }
   return childEnv + "=" + string(b), nil
}

// childMode reports whether this process was started as one of the re-executed children,
// and runs it if so. Called from main before the FlagSet exists: a child passes no
// arguments, so there is nothing for the FlagSet to parse.
//
// It is also the ONLY place a child payload is validated. Each mode names exactly the
// fields it needs, so a malformed spec fails here with one message rather than in
// whichever worker happened to trip over it. An error means a spawn bug, so main exits 2.
func childMode() (code int, ok bool, err error) {
   s := os.Getenv(childEnv)
   if s == "" {
      return 0, false, nil
   }

   var spec childSpec
   if err := json.Unmarshal([]byte(s), &spec); err != nil {
      return 0, true, fmt.Errorf("%s: %w", childEnv, err)
   }

   switch spec.Mode {
   case "probe":
      if len(spec.Descs) == 0 {
         return 0, true, fmt.Errorf("%s: probe with no descriptors", childEnv)
      }
      return runProbes(spec.Descs), true, nil

   case "sweep":
      // One descriptor, because a sweep drives one consumer. Families are indices into
      // dmFams, so the range is checked against it and not against a literal.
      if len(spec.Descs) != 1 {
         return 0, true, fmt.Errorf("%s: sweep needs exactly one descriptor, got %d",
            childEnv, len(spec.Descs))
      }
      if len(spec.Fams) == 0 || len(spec.Sets) == 0 {
         return 0, true, fmt.Errorf("%s: sweep needs families and sets", childEnv)
      }
      for _, f := range spec.Fams {
         if f < 0 || f >= len(dmFams) {
            return 0, true, fmt.Errorf("%s: family %d is not one of %d",
               childEnv, f, len(dmFams))
         }
      }
      return dmWorker(spec.Descs[0], spec.Fams, spec.Sets), true, nil

   case "p1":
      // Phase 1 is phase 2 with one empty OBF, and the empty value is what selects the
      // phase-1 argument shape, so exactly one is required and it must be empty.
      if len(spec.Descs) == 0 {
         return 0, true, fmt.Errorf("%s: p1 with no descriptors", childEnv)
      }
      if len(spec.Obfs) != 1 || spec.Obfs[0] != "" {
         return 0, true, fmt.Errorf("%s: p1 needs exactly one empty OBF slot, got %d",
            childEnv, len(spec.Obfs))
      }
      return dpWorker(spec.Mode, 0, spec.Obfs, spec.Descs), true, nil

   case "p2":
      // One OBF per candidate, so any non-empty list will not do: the worker indexes
      // obfs[oi] for every (descriptor, OBF, half) triple.
      if len(spec.Descs) == 0 || len(spec.Obfs) == 0 {
         return 0, true, fmt.Errorf("%s: p2 needs descriptors and OBFs", childEnv)
      }
      if spec.Start < 0 {
         return 0, true, fmt.Errorf("%s: p2 start %d is negative", childEnv, spec.Start)
      }
      return dpWorker(spec.Mode, spec.Start, spec.Obfs, spec.Descs), true, nil
   }
   return 0, true, fmt.Errorf("%s: unknown mode %q", childEnv, spec.Mode)
}

// emit prints one row. The only error Encode can return here is a write to a closed pipe,
// which no caller could act on and which the parent already reports as a missing end row.
func emit(r childRow) { _ = childEnc.Encode(r) }

// isHex reports whether s decodes as hex bytes.
func isHex(s string) bool {
   _, err := hex.DecodeString(s)
   return err == nil
}

// isHex32 reports whether s is exactly 0x20 bytes of hex, the shape of every 0x20-byte
// buffer a child prints. Length alone is not the test: hex.DecodeString returns the bytes
// it did decode alongside its error, so a 66-character field with a bad final byte yields a
// well-formed 0x20 bytes plus an error.
func isHex32(s string) bool { return len(s) == 0x40 && isHex(s) }

// ------------------------------------------------------------- the wire

// childRow is one line a child prints, and the only thing a parent parses. A kind sets only
// the fields it carries; on the far side an absent field is the zero value.
//
//   k=ok        p1/p2  d descriptor, i OBF, h key half, b key buffer then output buffer
//   k=reject    p1/p2  d, i, h, r rc, s the status dword
//   k=accept    probe  d, b[0] A output, b[1] B output, s A/B/C status, e the verdict detail
//   k=none      probe  d, e why no verdict was reached
//   k=meta      sweep  e one human log line
//   k=live      sweep  f family, i set index, d the live set rva
//   k=nolive    sweep  f family, i how many sets were live
//   k=out       sweep  f family, i licence, h forced nibble, r rc, s status, b[0] value
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
   RC   uint32   `json:"r,omitempty"`
   Msg  string   `json:"e,omitempty"`
}

// readRows parses a child's stdout. Blank lines are skipped. Every b and s entry must be
// hex, because every caller below decodes those fields without a second look: a malformed
// one is a parse failure here rather than a silent "no match" ten steps later.
//
// A final line that does not parse is dropped, not fatal: it has no trailing newline, so it
// is a row a killed child was still writing, and discarding it keeps the rows before it.
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

// log renders a row for a step's log file. The wire form is already the JSON line; this
// exists so a caller does not have to marshal-and-ignore-error at the log site.
func (r childRow) log() string {
   b, _ := json.Marshal(r)
   return string(b)
}

// childSpec is a child's whole payload. Descs is per-mode: descriptor VAs for "probe",
// "p1" and "p2", and the single consumer descRVA for "sweep". The remaining fields are
// read by the one mode that uses them and ignored by the rest.
//
// Obfs is a single "" for "p1", where the empty value selects the phase-1 argument shape,
// and the full OBF list for "p2".
type childSpec struct {
   Mode  string   `json:"mode"`            // probe | sweep | p1 | p2
   Descs []uint32 `json:"descs,omitempty"` // probe, p1, p2; sweep uses the one element
   Fams  []int    `json:"fams,omitempty"`  // sweep
   Sets  []uint32 `json:"sets,omitempty"`  // sweep
   Obfs  []string `json:"obfs,omitempty"`  // p1, p2
   Start int      `json:"start,omitempty"` // p2
}

// ------------------------------------------------------------ spawn helpers

// procOut is one collected child run. rc is -1 when the child produced no verdict: it was
// killed by the deadline, or it could not be started at all, which is the one case err
// reports.
type procOut struct {
   stdout []byte
   rc     int
   err    error
}

// runCollect spawns this binary as a child and returns its stdout. The child is identified
// by env alone and is passed no arguments; spec is encoded here, so no caller ever formats
// a payload and no child ever re-parses a hand-built string.
//
// A non-zero exit is reported as rc, not as an error: every child signals failure that way
// on purpose, and the caller parses stdout for the reason. err is non-nil only when the
// process could not be started or the spec could not be encoded.
//
// timeout > 0 bounds the run; -1's probe passes 0, because a deadline there would make a
// hang indistinguishable from a fault. stream, when non-nil, receives each stderr line as
// it arrives and before Wait, so a child that never exits still leaves its trace.
func runCollect(spec *childSpec, timeout time.Duration, stream func(string)) *procOut {
   if selfErr != nil {
      return &procOut{rc: -1, err: selfErr}
   }
   entry, err := childEnvFor(spec)
   if err != nil {
      return &procOut{rc: -1, err: err}
   }

   cmd := exec.Command(selfPath)
   // Last value wins: exec dedupes Env, case-insensitively on Windows, so an inherited
   // PRKF_CHILD is shadowed by this spawn's spec rather than needing to be removed.
   cmd.Env = append(os.Environ(), entry)
   var so bytes.Buffer
   cmd.Stdout = &so

   var er io.ReadCloser
   if stream != nil {
      if er, err = cmd.StderrPipe(); err != nil {
         return &procOut{rc: -1, err: err}
      }
   }
   if err := cmd.Start(); err != nil {
      return &procOut{rc: -1, err: err}
   }

   // The deadline does one thing - kill the child - and asks one question - did it fire?
   // That is all a context.Context was doing here, and a timer answers both without the
   // package. It is armed after Start because the callback dereferences cmd.Process,
   // which is nil until then.
   //
   // A Kill that fails means the child had already exited; the check below tolerates that
   // race anyway, so the error is dropped rather than reported as a failure to kill.
   var kill *time.Timer
   if timeout > 0 {
      kill = time.AfterFunc(timeout, func() { _ = cmd.Process.Kill() })
   }

   if er != nil {
      sc := bufio.NewScanner(er)
      sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
      for sc.Scan() {
         stream("  " + sc.Text())
      }
      // The scanner's error is the only signal that the trace ended early. Dropped, it
      // would make a truncated trace indistinguishable from a complete one.
      if serr := sc.Err(); serr != nil {
         stream(fmt.Sprintf("  TRACE TRUNCATED: %v", serr))
      }
   }

   // Reading stderr to EOF before Wait is the documented pattern: Wait closes the pipe, so
   // every trace line is out of the child before the rows are read.
   runErr := cmd.Wait()

   // Stop reports whether the timer was still pending. False means it fired, so the child
   // was killed on the deadline: this run has no verdict, and is not a start failure
   // either. The window between Wait returning and Stop is the same one ctx.Err() left, so
   // a child that finished exactly on the deadline is still reported as no-verdict.
   if kill != nil && !kill.Stop() {
      return &procOut{stdout: so.Bytes(), rc: -1}
   }

   p := &procOut{stdout: so.Bytes(), rc: -1}
   switch e := runErr.(type) {
   case nil:
      p.rc = 0
   case *exec.ExitError:
      p.rc = e.ExitCode()
   default:
      p.err = runErr
   }
   return p
}

// child.go end
