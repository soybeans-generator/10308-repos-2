// main.go marker preserve

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
// percentage of the distinct GPQA Diamond score values: rows are ordered by
// GPQA Diamond descending, the top topPct% of distinct scores (each value
// counted once, however many rows carry it) are kept, and those rows are
// re-sorted by throughput before printing. Counting distinct values means a
// score many providers tie on cannot crowd the score below it out of the
// cut. The -top flag has no default: it must be given on the command line.
// The percentage is printed in the output header and the resolved counts in
// the run log, so the cut is never implicit.
var topPct = &topFlag{}

func init() {
   flag.Var(topPct, "top", "percentage of distinct GPQA Diamond score values kept after ranking (required, no default)")
}

// keptValues resolves the topPct cut against a field's distinct score
// values, sorted descending. It returns the lowest value that stays (the
// cutoff) and how many distinct values that is, both in whatever integral
// unit the caller supplies (main passes tenths of a percent). The
// percentage is taken over the distinct values — a score many rows tie on
// counts once — so a crowded top score cannot consume the whole quota and
// crowd the next score down out of the cut. ceil(count * topPct/100) values
// are kept, never fewer than one (a nonempty field keeps its best value)
// and never more than the number of values itself. A nonpositive count
// keeps 0; the caller's empty-field guard handles that case.
func keptValues(sorted []int) (cutoff int, kept int) {
   if len(sorted) == 0 {
      return 0, 0
   }
   kept = min(len(sorted), max(1, int(math.Ceil(float64(len(sorted))*topPct.value/100))))
   return sorted[kept-1], kept
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

   // --- 3. Rank by score, then cut. The percentage is applied to the
   // distinct score values — each value counts once, however many rows carry
   // it — not to the rows, so a top score many providers tie on cannot crowd
   // the next score down out of the cut. Every row at or above the cutoff
   // value stays, so a value is never split partway.
   totalRows := len(rows)
   slices.SortFunc(rows, func(a, b *row) int {
      return cmp.Compare(b.GPQA, a.GPQA)
   })

   // Distinct scores, descending, in tenths of a percent — the unit the
   // report prints (%.1f%%). rows is now score-ordered, so equal scores are
   // adjacent and each value enters once. Rounding to the printed unit is
   // what makes "same value" well-defined: an interpolated median is not
   // always bit-identical to a stored score (median of 92 and 94 is
   // 93.00000000000001, not 93), and an exact `!=` would split that tie.
   values := make([]int, 0, len(rows))
   for _, r := range rows {
      v := int(math.Round(r.GPQA * 1000))
      if len(values) == 0 || v != values[len(values)-1] {
         values = append(values, v)
      }
   }

   cutoff, valuesKept := keptValues(values)
   kept := 0
   for kept < len(rows) && int(math.Round(rows[kept].GPQA*1000)) >= cutoff {
      kept++
   }
   rows = rows[:kept]

   // A run that ranks nothing is a misconfiguration, not a result: say so
   // rather than printing a bare header. With any row above, keptValues
   // never returns fewer than one value, so this can only fire on an empty
   // field; kept anyway.
   if len(rows) == 0 {
      return fmt.Errorf("no provider rows to rank: %d candidates, %d skipped for absent data, %d rows",
         len(cands), skipped, totalRows)
   }

   // The cut's size and bounds: the distinct-value and kept-row counts that
   // topPct% resolved to, and the highest and lowest GPQA Diamond score
   // among the kept rows. rows is still score-ordered here, so the first row
   // carries the highest and the last row the lowest — all of it must be
   // read before the throughput re-order below, which scrambles the
   // positions.
   fmt.Fprintf(os.Stderr, "\ntop %.0f%% of %d distinct scores: kept %d rows across %d value(s)\n",
      topPct.value, len(values), len(rows), valuesKept)
   fmt.Fprintf(os.Stderr, "highest gpqa diamond in top %.0f%%: %.1f%%\n", topPct.value, rows[0].GPQA*100)
   fmt.Fprintf(os.Stderr, "lowest gpqa diamond in top %.0f%%: %.1f%%\n", topPct.value, rows[len(rows)-1].GPQA*100)

   // --- 4. Order the kept rows by throughput, descending: the selection
   // above was by score; the printed order is by speed.
   slices.SortFunc(rows, func(a, b *row) int {
      return cmp.Compare(b.Throughput, a.Throughput)
   })

   // The header stays on the console; only the row items go to the file.
   fmt.Printf("top %.0f%% of distinct gpqa diamond scores, sorted by: throughput, descending\n\n", topPct.value)

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

// main.go marker preserve
