// api.go
package main

import (
   "cmp"
   "encoding/json"
   "fmt"
   "io"
   "net/http"
   "net/url"
   "slices"
)

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

// One request for the whole catalog (confirmed by capture).
const catalogURL = "https://openrouter.ai/api/frontend/v1/models/find?active=true"

// Per-model request for provider throughput stats (confirmed by capture).
// Response is {"data": [ {provider_name, stats: {p50_throughput, ...}}, ... ]}.
const statsURLTemplate = "https://openrouter.ai/api/frontend/v1/stats/endpoint" +
   "?latencyMetric=latency&perfWorkload=text_generation&variant=standard&permaslug=%s"

func httpGet(c *http.Client, url string) ([]byte, error) {
   req, err := http.NewRequest(http.MethodGet, url, nil)
   if err != nil {
      return nil, err
   }
   req.Header.Set("User-Agent", "tp-rank/1.0")
   resp, err := c.Do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   if resp.StatusCode != http.StatusOK {
      return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
   }
   return io.ReadAll(resp.Body)
}

// lowestP50 returns the slowest p50 in the kept provider set. Providers are
// kept fastest-first, so it is the last entry. Zero when there are none.
func lowestP50(s *score) float64 {
   if len(s.Providers) == 0 {
      return 0
   }
   return s.Providers[len(s.Providers)-1].P50
}

// ---------------------------------------------------------------------------
// Math / HTTP helpers
// ---------------------------------------------------------------------------

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

type benchmarks struct {
   AA *struct {
      IntelligenceIndex float64 `json:"intelligence_index"`
   } `json:"aa"`
}

// ---------------------------------------------------------------------------
// Working types
// ---------------------------------------------------------------------------

type candidate struct {
   slug         string
   name         string
   intelligence float64
}

// ---------------------------------------------------------------------------
// Catalog: single request -> all models -> open-weights 1M+ context candidates
// ---------------------------------------------------------------------------

func fetchCandidates(c *http.Client) ([]*candidate, int, error) {
   body, err := httpGet(c, catalogURL)
   if err != nil {
      return nil, 0, err
   }
   var resp findResponse
   if err := json.Unmarshal(body, &resp); err != nil {
      return nil, 0, fmt.Errorf("decoding catalog: %w", err)
   }

   total := len(resp.Data.Models)
   seen := make(map[string]bool)
   var cands []*candidate
   for _, m := range resp.Data.Models {
      // Open weights = weights published on Hugging Face.
      if m.Permaslug == "" || m.HfSlug == "" {
         continue
      }
      // Long context only: 1M tokens or more.
      if m.ContextLength < 1_000_000 {
         continue
      }
      // The catalog can contain duplicate entries per permaslug.
      if seen[m.Permaslug] {
         continue
      }
      seen[m.Permaslug] = true

      cd := &candidate{slug: m.Permaslug, name: m.Name}
      if b, ok := resp.Data.Benchmarks[m.Permaslug]; ok && b.AA != nil {
         cd.intelligence = b.AA.IntelligenceIndex
      }
      cands = append(cands, cd)
   }
   return cands, total, nil
}

type catalogModel struct {
   Permaslug     string `json:"permaslug"`
   Name          string `json:"name"`
   HfSlug        string `json:"hf_slug"` // non-empty == open weights
   ContextLength int    `json:"context_length"`
}

// ---------------------------------------------------------------------------
// Catalog types (from the models/find payload)
// ---------------------------------------------------------------------------

type findResponse struct {
   Data struct {
      Models     []catalogModel        `json:"models"`
      Benchmarks map[string]benchmarks `json:"benchmarks"`
   } `json:"data"`
}

// Per-provider p50 throughput, tokens/sec.
type providerStat struct {
   Provider string  `json:"provider"`
   P50      float64 `json:"p50_throughput"`
}

type score struct {
   Model        string  `json:"model"`
   Name         string  `json:"name"`
   Intelligence float64 `json:"intelligence"`
   // MedianP50 is the median across providers of p50 throughput,
   // tokens/sec.
   MedianP50 float64         `json:"median_p50_tps"`
   Providers []*providerStat `json:"providers"`
   Error     string          `json:"error,omitempty"`
}

// ---------------------------------------------------------------------------
// Providers: one request per candidate, sequential, no retry
// ---------------------------------------------------------------------------

func fetchScore(c *http.Client, cd *candidate, maxProviders int) *score {
   s := &score{Model: cd.slug, Name: cd.name, Intelligence: cd.intelligence}

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

// Per-provider p50 throughput, tokens/sec.
type statDetails struct {
   P50Throughput float64 `json:"p50_throughput"`
}

type statEndpoint struct {
   ProviderName string       `json:"provider_name"`
   Quantization string       `json:"quantization"`
   Stats        *statDetails `json:"stats"`
}

// ---------------------------------------------------------------------------
// Stats types (from the stats/endpoint payload, confirmed by capture)
// ---------------------------------------------------------------------------

type statsResponse struct {
   Data []statEndpoint `json:"data"`
}

// api.go
