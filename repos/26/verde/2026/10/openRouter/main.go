// main.go marker preserve
package main

import (
   "cmp"
   "encoding/json"
   "flag"
   "fmt"
   "log"
   "net/http"
   "net/url"
   "os"
   "slices"
   "strings"
   "time"
)

func main() {
   log.SetFlags(log.Ltime) // HMS only, no date

   providers := flag.Int("p", 10,
      "providers per model, fastest first (also the median's window; 0 = all)")
   minIntelligence := flag.Float64("i", 0,
      "minimum Artificial Analysis intelligence index, server-side filter (0 = no filter)")
   maxOutputPrice := flag.Float64("m", 10,
      "maximum output price in $/Mtok, server-side filter (0 = no filter)")
   flag.Parse()

   // No flags -> do nothing.
   if flag.NFlag() == 0 {
      flag.Usage()
      return
   }

   f := filters{
      minIntelligenceIndex: *minIntelligence,
      maxOutputPrice:       *maxOutputPrice,
   }
   if err := run(*providers, f); err != nil {
      fmt.Fprintf(os.Stderr, "%v\n", err)
      os.Exit(1)
   }
}

func run(maxProviders int, f filters) error {
   client := &http.Client{Timeout: 30 * time.Second}

   // --- 1. Catalog: one request. The intelligence index and output
   // price filters are applied by the server via query params; the
   // open-weights narrowing stays client-side. Context and pricing
   // come from this response as well, at the model level.
   cands, total, err := fetchCandidates(client, f)
   if err != nil {
      return fmt.Errorf("catalog: %w", err)
   }
   if len(cands) == 0 {
      return fmt.Errorf("no candidates matched (%d models in catalog)", total)
   }

   // --- 2. Providers: sequential, one request per candidate. A failed
   // request is reported as a log line — like the GET lines — and
   // skipped; no retries. All log output (stderr) happens here.
   var scored []*score
   for _, cd := range cands {
      s := fetchScore(client, cd, maxProviders)
      if s.Error != "" {
         log.Printf("error: %s: %s", s.Model, s.Error)
         continue
      }
      scored = append(scored, s)
   }

   // --- 3. Sort by the median p50 across the kept providers,
   // descending. A model with fewer providers than the flag is ranked
   // on the median of whatever it has, so a small provider pool isn't
   // an automatic penalty.
   slices.SortFunc(scored, func(a, b *score) int {
      return cmp.Compare(b.MedianP50, a.MedianP50)
   })

   // Everything from here on is buffered and written to stdout in a
   // single shot at the end, so the report lands strictly after the
   // last log line regardless of stream buffering.
   var out strings.Builder

   // Header, wrapped so no line runs long. The catalog count is after
   // the server-side filters; the candidate count is after the
   // open-weights narrowing on top of those. The filter list beneath
   // spells out every filter that produced the candidate count.
   fmt.Fprintf(&out, "%d models in catalog after server-side filters\n", total)
   fmt.Fprintf(&out, "%d open-weights candidates after all filters:\n", len(cands))
   fmt.Fprintf(&out, "context at least 1M\n")
   if f.minIntelligenceIndex > 0 {
      fmt.Fprintf(&out, "minimum intelligence index %.4g\n", f.minIntelligenceIndex)
   }
   if f.maxOutputPrice > 0 {
      fmt.Fprintf(&out, "maximum output price $%.4g per Mtok\n", f.maxOutputPrice)
   }
   fmt.Fprintln(&out)

   // Say how the list was ordered, wrapped too.
   scope := fmt.Sprintf("fastest %d providers (or all if fewer)", maxProviders)
   if maxProviders <= 0 {
      scope = "all providers"
   }
   fmt.Fprintf(&out, "sorted by: median p50 tps across the\n%s, descending\n\n", scope)

   for _, s := range scored {
      fmt.Fprintf(&out, "model: %s\n", s.Model)
      fmt.Fprintf(&out, "intelligence: %.1f\n", s.Intelligence)
      fmt.Fprintf(&out, "context: %d\n", s.Context)
      fmt.Fprintf(&out, "price: $%.2f in / $%.2f out per Mtok\n", s.InputPrice, s.OutputPrice)
      fmt.Fprintf(&out, "median p50 tps: %.1f (%d providers)\n", s.MedianP50, len(s.Providers))
      fmt.Fprintf(&out, "P50 TPS:\n")
      for _, p := range s.Providers {
         fmt.Fprintf(&out, "  %s: %.1f\n", p.Provider, p.P50)
      }
      fmt.Fprintln(&out)
   }

   // Single flush: the whole report follows the log lines.
   fmt.Fprint(os.Stdout, out.String())
   return nil
}

// ---------------------------------------------------------------------------
// Providers: one request per candidate, sequential, no retry
// ---------------------------------------------------------------------------

// Per-provider p50 throughput, tokens/sec.
type providerStat struct {
   Provider string  `json:"provider"`
   P50      float64 `json:"p50_throughput"`
}

type score struct {
   Model        string  `json:"model"`
   Name         string  `json:"name"`
   Intelligence float64 `json:"intelligence"`
   Context      int     `json:"context_length"`
   InputPrice   float64 `json:"input_price_per_mtok"`
   OutputPrice  float64 `json:"output_price_per_mtok"`
   // MedianP50 is the median across providers of p50 throughput,
   // tokens/sec.
   MedianP50 float64         `json:"median_p50_tps"`
   Providers []*providerStat `json:"providers"`
   Error     string          `json:"error,omitempty"`
}

func fetchScore(c *http.Client, cd *candidate, maxProviders int) *score {
   s := &score{
      Model:        cd.slug,
      Name:         cd.name,
      Intelligence: cd.intelligence,
      Context:      cd.context,
      InputPrice:   cd.inputPrice,
      OutputPrice:  cd.outputPrice,
   }

   u := fmt.Sprintf(statsURLTemplate, url.QueryEscape(cd.slug))
   body, err := httpGet(c, u)
   if err != nil {
      s.Error = err.Error()
      return s
   }

   var sr statsResponse
   if err := json.Unmarshal(body, &sr); err != nil {
      s.Error = "decode: " + err.Error()
      return s
   }

   // One p50 throughput value per provider. The stats endpoint returns
   // several rows for the same provider, while the web client shows a
   // single option per provider, so duplicates collapse to the slowest —
   // that is what you actually get.
   idx := make(map[string]int)
   for _, ep := range sr.Data {
      if ep.Stats == nil {
         continue // no stats -> no data -> excluded
      }
      if i, ok := idx[ep.ProviderName]; ok {
         if ep.Stats.P50Throughput < s.Providers[i].P50 {
            s.Providers[i].P50 = ep.Stats.P50Throughput
         }
         continue
      }
      idx[ep.ProviderName] = len(s.Providers)
      s.Providers = append(s.Providers, &providerStat{Provider: ep.ProviderName, P50: ep.Stats.P50Throughput})
   }

   // Providers are listed fastest first.
   slices.SortFunc(s.Providers, func(a, b *providerStat) int {
      return cmp.Compare(b.P50, a.P50)
   })
   // Only the fastest maxProviders providers are kept, so the median
   // covers the same set that gets printed.
   if maxProviders > 0 && maxProviders < len(s.Providers) {
      s.Providers = s.Providers[:maxProviders]
   }

   // The median needs ascending order.
   p50s := make([]float64, len(s.Providers))
   for i, p := range s.Providers {
      p50s[i] = p.P50
   }
   slices.Sort(p50s)
   s.MedianP50 = percentile(p50s, 50)
   return s
}

// ---------------------------------------------------------------------------
// Stats types (from the stats/endpoint payload, confirmed by capture)
// ---------------------------------------------------------------------------

// Per-provider p50 throughput, tokens/sec.
type statDetails struct {
   P50Throughput float64 `json:"p50_throughput"`
}

type statEndpoint struct {
   ProviderName string       `json:"provider_name"`
   Quantization string       `json:"quantization"`
   Stats        *statDetails `json:"stats"`
}

type statsResponse struct {
   Data []statEndpoint `json:"data"`
}

// main.go marker preserve
