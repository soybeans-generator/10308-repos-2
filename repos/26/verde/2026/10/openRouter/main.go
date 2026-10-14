// main.go
package main

import (
   "cmp"
   "flag"
   "fmt"
   "net/http"
   "os"
   "slices"
   "time"
)

func main() {
   n := flag.Int("n", 0,
      "number of models to output (top N by intelligence; 0 = all)")
   providers := flag.Int("p", 10,
      "providers per model, fastest first (also the median's window; 0 = all)")
   flag.Parse()

   // No flags -> do nothing.
   if flag.NFlag() == 0 {
      flag.Usage()
      return
   }

   if err := run(*n, *providers); err != nil {
      fmt.Fprintf(os.Stderr, "%v\n", err)
      os.Exit(1)
   }
}

func run(n, maxProviders int) error {
   client := &http.Client{Timeout: 30 * time.Second}

   // --- 1. Catalog: one request, every model, narrowed to open weights.
   cands, total, err := fetchCandidates(client)
   if err != nil {
      return fmt.Errorf("catalog: %w", err)
   }
   fmt.Fprintf(os.Stderr, "%d models in catalog, %d open-weights 1M+ context candidates\n",
      total, len(cands))
   if len(cands) == 0 {
      return fmt.Errorf("no candidates matched")
   }

   // --- 2. Providers: sequential, one request per candidate. A failed
   // request is reported and skipped — no retries.
   var scored []*score
   for i, cd := range cands {
      s := fetchScore(client, cd, maxProviders)
      fmt.Fprintf(os.Stderr, "[%d/%d] %s ", i+1, len(cands), cd.slug)
      if s.Error != "" {
         fmt.Fprintf(os.Stderr, "error: %s\n", s.Error)
         continue
      }
      fmt.Fprintf(os.Stderr, "\n")
      scored = append(scored, s)
   }

   // --- 3. Keep the top N by intelligence, descending.
   slices.SortFunc(scored, func(a, b *score) int {
      return cmp.Compare(b.Intelligence, a.Intelligence)
   })
   if n > 0 && n < len(scored) {
      scored = scored[:n]
   }
   fmt.Fprintf(os.Stderr, "keeping %d models by intelligence\n", len(scored))

   // --- 4. Sort the survivors by the slowest kept provider's p50,
   // descending.
   slices.SortFunc(scored, func(a, b *score) int {
      return cmp.Compare(lowestP50(b), lowestP50(a))
   })

   // Say how the list was ordered.
   scope := fmt.Sprintf("fastest %d providers", maxProviders)
   if maxProviders <= 0 {
      scope = "all providers"
   }
   fmt.Printf("sorted by: lowest p50 tps across the %s, descending\n\n", scope)

   for _, s := range scored {
      fmt.Printf("model: %s\n", s.Model)
      fmt.Printf("intelligence: %.1f\n", s.Intelligence)
      fmt.Printf("P50 TPS:\n")
      for _, p := range s.Providers {
         fmt.Printf("  %s: %.1f\n", p.Provider, p.P50)
      }
      fmt.Println()
   }

   return nil
}

// main.go
