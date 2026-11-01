package main

import (
   "cmp"
   "encoding/json"
   "fmt"
   "io"
   "log"
   "net/http"
   "net/url"
   "os"
   "slices"
   "strconv"
   "strings"
   "time"
)

// The model page URL names a model by its short slug,
// deepseek/deepseek-v4.1-flash-1017, but stats/endpoint only answers to the
// dated permaslug, deepseek/deepseek-v4.1-flash-20261017. The catalog is the
// only map between them, so it is always the first request.
const (
   catalogURL = "https://openrouter.ai/api/frontend/v1/models/find"

   statsURL = "https://openrouter.ai/api/frontend/v1/stats/endpoint" +
      "?perfWorkload=text_generation&permaslug=%s"
)

// fetchPermaslug looks slug up in the catalog and returns the permaslug that
// stats/endpoint answers to.
func fetchPermaslug(c *http.Client, slug string) (string, error) {
   body, err := get(c, catalogURL)
   if err != nil {
      return "", err
   }
   var cat findResponse
   if err := json.Unmarshal(body, &cat); err != nil {
      return "", err
   }
   for _, cm := range cat.Data.Models {
      if strings.EqualFold(cm.Slug, slug) || strings.EqualFold(cm.Permaslug, slug) {
         return cm.Permaslug, nil
      }
   }
   return "", fmt.Errorf("%q not in catalog (%d models)", slug, len(cat.Data.Models))
}

func get(c *http.Client, u string) ([]byte, error) {
   req, err := http.NewRequest(http.MethodGet, u, nil)
   if err != nil {
      return nil, err
   }
   log.Println(req.Method, req.URL)
   resp, err := c.Do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   if resp.StatusCode != http.StatusOK {
      return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, req.URL)
   }
   return io.ReadAll(resp.Body)
}

func main() {
   log.SetFlags(log.Ltime) // HMS only, no date

   if len(os.Args) != 2 {
      fmt.Fprintf(os.Stderr, "usage: %s <model-url>\n", os.Args[0])
      os.Exit(2)
   }
   if err := run(os.Args[1]); err != nil {
      fmt.Fprintln(os.Stderr, err)
      os.Exit(1)
   }
}

// perTokToMTok converts a per-token price string into $/Mtok.
func perTokToMTok(s string) float64 {
   v, err := strconv.ParseFloat(s, 64)
   if err != nil || v < 0 {
      return 0
   }
   return v * 1_000_000
}

func run(rawURL string) error {
   client := &http.Client{Timeout: 30 * time.Second}

   slug, err := slugFromURL(rawURL)
   if err != nil {
      return err
   }
   permaslug, err := fetchPermaslug(client, slug)
   if err != nil {
      return err
   }
   if permaslug != slug {
      log.Printf("resolved %s -> %s", slug, permaslug)
   }
   provs, err := fetchProviders(client, permaslug)
   if err != nil {
      return err
   }
   if len(provs) == 0 {
      return fmt.Errorf("%s: no provider throughput data", permaslug)
   }

   for i, p := range provs {
      if i > 0 {
         fmt.Println()
      }
      fmt.Printf("provider: %s\n", p.name)
      fmt.Printf("output/M: $%.2f\n", p.outputPrice)
      fmt.Printf("P50 TPS: %.0f\n", p.p50)
   }
   return nil
}

// slugFromURL takes the last two path segments, which is <author>/<model> for
// both /author/model and /models/author/model.
func slugFromURL(raw string) (string, error) {
   u, err := url.Parse(strings.TrimSpace(raw))
   if err != nil {
      return "", err
   }
   segs := strings.Split(strings.Trim(u.Path, "/"), "/")
   if len(segs) < 2 || segs[len(segs)-2] == "" || segs[len(segs)-1] == "" {
      return "", fmt.Errorf("%q: no model in URL, want openrouter.ai/<author>/<model>", raw)
   }
   return segs[len(segs)-2] + "/" + segs[len(segs)-1], nil
}

type catalogModel struct {
   Slug      string `json:"slug"`
   Permaslug string `json:"permaslug"`
}

type findResponse struct {
   Data struct {
      Models []catalogModel `json:"models"`
   } `json:"data"`
}

type provider struct {
   name        string
   p50         float64
   outputPrice float64 // $/Mtok
}

// fetchProviders returns every provider with throughput, fastest first.
func fetchProviders(c *http.Client, permaslug string) ([]provider, error) {
   body, err := get(c, fmt.Sprintf(statsURL, url.QueryEscape(permaslug)))
   if err != nil {
      return nil, err
   }
   var sr statsResponse
   if err := json.Unmarshal(body, &sr); err != nil {
      return nil, err
   }

   // A provider appears once per quantization, so duplicates collapse to the
   // slowest one — that is what you actually get from that provider.
   idx := map[string]int{}
   var out []provider
   for _, ep := range sr.Data {
      if ep.ProviderName == "" || ep.Stats == nil || ep.Stats.P50Throughput <= 0 {
         continue
      }
      p := provider{
         name:        ep.ProviderName,
         p50:         ep.Stats.P50Throughput,
         outputPrice: perTokToMTok(ep.Pricing.Completion),
      }
      if i, seen := idx[p.name]; seen {
         if p.p50 < out[i].p50 {
            out[i] = p
         }
         continue
      }
      idx[p.name] = len(out)
      out = append(out, p)
   }
   slices.SortFunc(out, func(a, b provider) int { return cmp.Compare(b.p50, a.p50) })
   return out, nil
}

type statsResponse struct {
   Data []struct {
      ProviderName string `json:"provider_name"`
      Pricing      struct {
         Completion string `json:"completion"`
      } `json:"pricing"`
      Stats *struct {
         P50Throughput float64 `json:"p50_throughput"`
      } `json:"stats"`
   } `json:"data"`
}
