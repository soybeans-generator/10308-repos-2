// main.go marker - preserve

package main

import (
   "cmp"
   "flag"
   "fmt"
   "math"
   "net/http"
   "os"
   "slices"
   "strconv"
   "time"
)

// outputFile receives the ranked rows: model / provider / gpqa diamond /
// throughput per row. Everything else — the filter report, the
// per-candidate progress blocks, the cut's bounds, and the output header —
// stays on the console.
const outputFile = "output.txt"

// topPct is how much of the ranked field the output carries, as a
// percentage of all provider rows: every row is ordered by GPQA Diamond
// descending, the first topPct% are kept, and those are re-sorted by
// throughput before printing. The -top flag has no default: it must be
// given on the command line. The percentage is printed in the output
// header and the resolved row count in the run log, so the cut is never
// implicit.
var topPct = &topFlag{}

func init() {
   flag.Var(topPct, "top", "percentage of provider rows kept after ranking by GPQA Diamond (required, no default)")
}

// keptRows resolves the topPct cut against a field of totalRows rows:
// ceil(totalRows * topPct/100), but never fewer than 1 — a nonempty field
// always keeps its best row — and never more than totalRows itself. A
// nonpositive totalRows keeps 0; the caller's empty-field guard handles
// that case, so the truncating slice never overruns.
func keptRows(totalRows int) int {
   if totalRows <= 0 {
      return 0
   }
   return min(totalRows, max(1, int(math.Ceil(float64(totalRows)*topPct.value/100))))
}

func main() {
   flag.Parse()
   if !topPct.set {
      flag.Usage()
      return
   }
   if err := run(); err != nil {
      fmt.Fprintf(os.Stderr, "%v\n", err)
      os.Exit(1)
   }
}

// percentile returns the p-th percentile of ascending-sorted data with
// linear interpolation (numpy's default method): fractional index
// i = (p/100) * (n-1), interpolate between neighbors.
func percentile(sorted []float64, p float64) float64 {
   n := len(sorted)
   if n == 0 {
      return 0
   }
   if n == 1 {
      return sorted[0]
   }
   i := p / 100 * float64(n-1)
   lo := int(i)
   if lo+1 >= n {
      return sorted[n-1]
   }
   frac := i - float64(lo)
   return sorted[lo] + frac*(sorted[lo+1]-sorted[lo])
}

func run() error {
   client := &http.Client{Timeout: 30 * time.Second}

   // --- 1. Catalog: one request, three filters — one server-side (the
   // context floor), two client-side (open weights, dedupe). filterReport
   // names each filter and its effect, so no count is mistaken for the
   // size of the whole catalog.
   cands, stats, err := fetchCandidates(client)
   if err != nil {
      return fmt.Errorf("catalog: %w", err)
   }
   fmt.Fprint(os.Stderr, filterReport(stats))
   if len(cands) == 0 {
      return fmt.Errorf("no candidates after filtering: %d models returned for context >= %d, %d dropped as closed weights, %d as duplicate slugs",
         stats.AfterContext, minContext, stats.DroppedClosed, stats.DroppedDuplicate)
   }

   // --- 2. One block of lines per candidate: the header and the model's
   // context window are printed before the requests so a slow candidate is
   // visible while it is in flight, the outcome lines after the response.
   //
   // A candidate with no data recorded is logged and skipped; any other
   // failure aborts the run — no retries.
   var rows []*row
   skipped := 0
   for i, cd := range cands {
      fmt.Fprintf(os.Stderr, "\n[%d/%d] %s\n", i+1, len(cands), cd.slug)
      fmt.Fprintf(os.Stderr, "  %-30s %d tokens\n", "model context window:", cd.contextLength)

      rs, scoredProviders, err := fetchRows(client, &cd)
      if err != nil {
         if skippable(err) {
            fmt.Fprintf(os.Stderr, "  %-30s %v\n", "skipped:", err)
            skipped++
            continue
         }
         return fmt.Errorf("stats %s: %w", cd.slug, err)
      }

      // Three counts in the order a provider is eliminated: scored on GPQA,
      // of those ranked (one row each, having cleared the throughput join),
      // and the remainder whose endpoint carries no throughput measurement.
      // Printing the second and third together is what makes a zero
      // self-explanatory rather than a bare number.
      fmt.Fprintf(os.Stderr, "  %-30s %d\n", "providers with a GPQA score:", scoredProviders)
      fmt.Fprintf(os.Stderr, "  %-30s %d\n", "provider rows with throughput:", len(rs))
      fmt.Fprintf(os.Stderr, "  %-30s %d\n", "providers without throughput:", scoredProviders-len(rs))
      rows = append(rows, rs...)
   }

   // --- 3. Rank by score, then cut: order every provider row by GPQA
   // Diamond descending and keep the first topPct% of them — keptRows
   // resolves the percentage to a row count, rounded up.
   totalRows := len(rows)
   slices.SortFunc(rows, func(a, b *row) int {
      return cmp.Compare(b.GPQA, a.GPQA)
   })
   if keep := keptRows(totalRows); keep < len(rows) {
      rows = rows[:keep]
   }

   // A run that ranks nothing is a misconfiguration, not a result: say so
   // rather than printing a bare header. (Delete this block if an empty
   // list should exit 0.)
   if len(rows) == 0 {
      return fmt.Errorf("no provider rows to rank: %d candidates, %d skipped for absent data, %d rows",
         len(cands), skipped, totalRows)
   }

   // The cut's size and bounds: how many rows topPct% resolved to, and the
   // highest and lowest GPQA Diamond score among them. rows is still
   // score-ordered here, so the first row carries the highest and the last
   // row the lowest — all of it must be read before the throughput
   // re-order below, which scrambles the positions.
   fmt.Fprintf(os.Stderr, "\ntop %.0f%% of %d provider rows: kept %d\n", topPct.value, totalRows, len(rows))
   fmt.Fprintf(os.Stderr, "highest gpqa diamond in top %.0f%%: %.1f%%\n", topPct.value, rows[0].GPQA*100)
   fmt.Fprintf(os.Stderr, "lowest gpqa diamond in top %.0f%%: %.1f%%\n", topPct.value, rows[len(rows)-1].GPQA*100)

   // --- 4. Order the kept rows by throughput, descending: the selection
   // above was by score; the printed order is by speed.
   slices.SortFunc(rows, func(a, b *row) int {
      return cmp.Compare(b.Throughput, a.Throughput)
   })

   // The header stays on the console; only the row items go to the file.
   fmt.Printf("top %.0f%% by gpqa diamond score, sorted by: throughput, descending\n\n", topPct.value)

   f, err := os.Create(outputFile)
   if err != nil {
      return fmt.Errorf("creating output file: %w", err)
   }
   defer f.Close()

   for _, r := range rows {
      fmt.Fprintf(f, "model: %s\n", r.Model)
      fmt.Fprintf(f, "provider: %s\n", r.Provider)
      fmt.Fprintf(f, "gpqa diamond: %.1f%%\n", r.GPQA*100)
      fmt.Fprintf(f, "throughput: %.1f tok/s\n", r.Throughput)
      fmt.Fprintln(f)
   }

   return nil
}

// topFlag is a flag.Value that remembers whether it was set, so an absent
// -top (distinct from -top 0, say) can be told apart from a supplied one.
type topFlag struct {
   value float64
   set   bool
}

func (f *topFlag) Set(s string) error {
   v, err := strconv.ParseFloat(s, 64)
   if err != nil {
      return err
   }
   f.value = v
   f.set = true
   return nil
}

func (f *topFlag) String() string {
   return strconv.FormatFloat(f.value, 'g', -1, 64)
}

// main.go marker - preserve
