// openrouter.go marker preserve
package main

import (
   "encoding/json"
   "fmt"
   "io"
   "log"
   "net/http"
   "net/url"
   "strconv"
)

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

// One request for the whole catalog (confirmed by capture). The
// min_intelligence_index / max_output_price filters are appended by
// catalogURL() when the corresponding flags are set — both are documented
// server-side filters on the models list endpoint. The 1M minimum
// context length is likewise a documented server-side filter ("context"
// param) and is baked into the base URL.
const catalogBaseURL = "https://openrouter.ai/api/frontend/v1/models/find" +
   "?context=1000000"

// Per-model request for provider throughput stats. Only two params are
// needed: permaslug (which model) and perfWorkload (which workload the
// throughput is measured on). latencyMetric and variant were tested
// and dropped — omitting either alone reproduces the baseline exactly,
// omitting perfWorkload changes the values.
const statsURLTemplate = "https://openrouter.ai/api/frontend/v1/stats/endpoint" +
   "?perfWorkload=text_generation&permaslug=%s"

// catalogURL appends the active server-side filters to the base URL.
func catalogURL(f filters) string {
   u, err := url.Parse(catalogBaseURL)
   if err != nil {
      return catalogBaseURL // constant URL; parse cannot fail
   }
   q := u.Query()
   if f.minIntelligenceIndex > 0 {
      q.Set("min_intelligence_index", formatFloat(f.minIntelligenceIndex))
   }
   if f.maxOutputPrice > 0 {
      q.Set("max_output_price", formatFloat(f.maxOutputPrice))
   }
   u.RawQuery = q.Encode()
   return u.String()
}

// formatFloat renders 33.0 as "33" and 2.5 as "2.5", so the logged URLs
// match the documented examples.
func formatFloat(v float64) string {
   return strconv.FormatFloat(v, 'f', -1, 64)
}

func httpGet(c *http.Client, rawURL string) ([]byte, error) {
   req, err := http.NewRequest(http.MethodGet, rawURL, nil)
   if err != nil {
      return nil, err
   }
   req.Header.Set("User-Agent", "tp-rank/1.0")
   log.Println(req.Method, req.URL)
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

// perTokToMTok converts a per-token price string ("0.000001") into a
// per-million-token dollar figure (1.0). Empty or malformed strings
// become 0.
func perTokToMTok(s string) float64 {
   v, err := strconv.ParseFloat(s, 64)
   if err != nil || v < 0 {
      return 0
   }
   return v * 1_000_000
}

// ---------------------------------------------------------------------------
// Math helpers
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
// Catalog: one request -> server-filtered -> open-weights candidates
// ---------------------------------------------------------------------------

type candidate struct {
   slug         string
   name         string
   intelligence float64
   context      int
   inputPrice   float64 // $/Mtok input
   outputPrice  float64 // $/Mtok output
}

// fetchCandidates requests the catalog with the server-side filters
// (context length, intelligence index, output price) already applied,
// then narrows it client-side to open-weights models. Context length
// and pricing are taken from here too: the model object carries
// context_length, and its nested default endpoint carries the pricing
// OpenRouter quotes for the model.
func fetchCandidates(c *http.Client, f filters) ([]*candidate, int, error) {
   body, err := httpGet(c, catalogURL(f))
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
      // The catalog can contain duplicate entries per permaslug.
      if seen[m.Permaslug] {
         continue
      }
      seen[m.Permaslug] = true

      cd := &candidate{
         slug:        m.Permaslug,
         name:        m.Name,
         context:     m.ContextLength,
         inputPrice:  perTokToMTok(m.Endpoint.Pricing.Prompt),
         outputPrice: perTokToMTok(m.Endpoint.Pricing.Completion),
      }
      if b, ok := resp.Data.Benchmarks[m.Permaslug]; ok && b.AA != nil {
         cd.intelligence = b.AA.IntelligenceIndex
      }
      cands = append(cands, cd)
   }
   return cands, total, nil
}

// ---------------------------------------------------------------------------
// Catalog types (from the models/find payload)
// ---------------------------------------------------------------------------

type catalogModel struct {
   Permaslug     string `json:"permaslug"`
   Name          string `json:"name"`
   HfSlug        string `json:"hf_slug"` // non-empty == open weights
   ContextLength int    `json:"context_length"`
   Endpoint      struct {
      Pricing struct {
         Prompt     string `json:"prompt"`
         Completion string `json:"completion"`
      } `json:"pricing"`
   } `json:"endpoint"`
}

// filters holds the server-side catalog filters. Zero values mean
// "don't filter" — the query parameter is simply omitted.
type filters struct {
   minIntelligenceIndex float64
   maxOutputPrice       float64
}

type findResponse struct {
   Data struct {
      Models     []catalogModel        `json:"models"`
      Benchmarks map[string]benchmarks `json:"benchmarks"`
   } `json:"data"`
}

// openrouter.go marker preserve
