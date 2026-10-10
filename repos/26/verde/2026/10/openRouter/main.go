// main.go marker preserve

package main

import (
   "cmp"
   "flag"
   "fmt"
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

// topN is how many models the output carries. Every model/provider
// combination is ordered by GPQA Diamond descending, then the minimum
// number of combinations is taken from the top of that ranking that
// contains topN distinct models. A model is counted once, however many
// combinations it contributes, and the walk stops at the first combination
// whose model would exceed the quota — nothing below that point is kept.
// The kept rows are then re-sorted by throughput before printing. The -top
// flag has no default: it must be given on the command line. The requested
// count and the count it resolved to are both logged, so the cut is never
// implicit.
var topN = &topFlag{}

func init() {
   flag.Var(topN, "top", "number of models kept (required, no default)")
}

func main() {
   flag.Parse()
   if !topN.set {
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

   // --- 3. Rank by score, then cut. Every combination is ordered by GPQA
   // Diamond descending and walked from the top; combinations are kept
   // until topN distinct models have been seen, and the walk stops at the
   // first combination whose model would exceed that quota. That is the
   // minimum number of combinations from the top of the ranking that
   // contains topN models: a model is counted once however many
   // combinations it contributes, and no combination below the stopping
   // point is kept. GPQA is not truncated or bucketed during selection,
   // only rounded at print time.
   totalRows := len(rows)
   scoredModels := make(map[string]bool)
   for _, r := range rows {
      scoredModels[r.Model] = true
   }
   distinctModels := len(scoredModels)

   slices.SortFunc(rows, func(a, b *row) int {
      return cmp.Compare(b.GPQA, a.GPQA)
   })

   kept := 0
   models := make(map[string]bool)
   var keptModels []string
   for _, r := range rows {
      if len(models) >= topN.value && !models[r.Model] {
         break // a new model past the quota -> the cut ends here
      }
      if !models[r.Model] {
         models[r.Model] = true
         keptModels = append(keptModels, r.Model)
      }
      kept++
   }
   rows = rows[:kept]

   // A run that keeps nothing is a misconfiguration, not a result: say so
   // rather than printing a bare header. The flag rejects a nonpositive
   // count, so this can only fire on an empty field; kept anyway.
   if len(rows) == 0 {
      return fmt.Errorf("no provider rows to rank: %d candidates, %d skipped for absent data, %d rows",
         len(cands), skipped, totalRows)
   }

   // The cut's result: how many models were requested, whether the catalog
   // held enough, and how many combinations that resolved to — followed by
   // the kept models in the order their best combinations ranked.
   if len(models) < topN.value {
      fmt.Fprintf(os.Stderr, "\ntop %d models requested but only %d distinct models scored: kept all %d combinations\n",
         topN.value, distinctModels, kept)
   } else {
      fmt.Fprintf(os.Stderr, "\ntop %d models by gpqa diamond: kept %d combinations\n", topN.value, kept)
   }
   for _, m := range keptModels {
      fmt.Fprintf(os.Stderr, "  %s\n", m)
   }

   // --- 4. Order the kept rows by throughput, descending: the selection
   // above was by score; the printed order is by speed.
   slices.SortFunc(rows, func(a, b *row) int {
      return cmp.Compare(b.Throughput, a.Throughput)
   })

   // The header stays on the console; only the row items go to the file.
   fmt.Printf("sorted by: throughput, descending\n\n")

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
   value int
   set   bool
}

func (f *topFlag) Set(s string) error {
   v, err := strconv.Atoi(s)
   if err != nil {
      return err
   }
   if v <= 0 {
      return fmt.Errorf("must be a positive count")
   }
   f.value = v
   f.set = true
   return nil
}

func (f *topFlag) String() string {
   return strconv.Itoa(f.value)
}

// main.go marker preserve
