// api.go marker - preserve

package main

import (
   "encoding/json"
   "errors"
   "fmt"
   "io"
   "net/http"
   "net/url"
)

// Per-permaslug stats, one request each — no HTML, no escaped-JSON brace
// counting. Both endpoints live in the same /api/frontend/v1/stats
// namespace the model page's own queries use, are reachable with no cookie
// and no API key (verified live: identical payload from a clean client),
// and answer with access-control-allow-origin: *; both are CDN-cached for
// an hour.
//
// The permaslug goes in the query string, so its "/" must be escaped to
// %2F, exactly as in the captured request. This is the opposite of the
// model page route, where PathEscape is wrong because the "/" is a path
// separator.
const scoresURLTemplate = "https://openrouter.ai/api/frontend/v1/stats/benchmark-scores?permaslug=%s"
const throughputURLTemplate = "https://openrouter.ai/api/frontend/v1/stats/throughput-comparison?permaslug=%s"

// ---------------------------------------------------------------------------
// Absent data: 200 responses that mean "skip this candidate", not "stop"
// ---------------------------------------------------------------------------

// These stats endpoints answer 200 with an empty payload for a permaslug
// that has nothing recorded yet. Captured:
//
//   GET benchmark-scores?permaslug=tencent%2Fhy4-preview-20260827
//   -> {"data":{"scores":[],"lookback_days":32}}
//
// Over a whole catalog that is routine — a newly published model has no
// benchmark runs and no traffic — so it must not abort the run. These
// sentinels mark it, and skippable is the single place that decides which
// errors mean "drop this candidate" rather than "stop".
//
// The line each fetcher draws is between a server that says it has no data
// (an empty array -> sentinel) and a server that no longer answers in the
// documented shape (a missing or null data object -> ordinary error). A
// genuine API change therefore still aborts loudly, instead of quietly
// emptying the output.
//
// errNoThroughput covers a throughput series that yields no measurement at
// all. It is deliberately distinct from a series that does carry
// measurements but not for any of the endpoints GPQA was scored on: the
// first is "nothing recorded", the second is a join that came up empty, and
// the per-candidate log reports them differently.
var (
   errNoScores     = errors.New("no benchmark scores")
   errNoGPQA       = errors.New("no gpqa_diamond scores")
   errNoThroughput = errors.New("no throughput stats")
)

// fetchThroughput returns, per endpoint id, the tokens/sec of the most
// recent day that endpoint was measured on. The ids parameter the endpoint
// also accepts is ignored server-side (verified: byte-identical payload
// with and without it), so one request covers every endpoint of the model.
//
// A payload that yields no measurement at all — an empty series, or points
// whose y maps are all empty — returns errNoThroughput, which the caller
// treats as a skip rather than letting the candidate collapse silently to
// zero rows.
func fetchThroughput(c *http.Client, permaslug string) (map[string]float64, error) {
   body, err := httpGet(c, fmt.Sprintf(throughputURLTemplate, url.PathEscape(permaslug)))
   if err != nil {
      return nil, err
   }
   var resp throughputResponse
   if err := json.Unmarshal(body, &resp); err != nil {
      return nil, fmt.Errorf("decoding throughput stats: %w", err)
   }
   if resp.Data == nil {
      return nil, fmt.Errorf("no data array in throughput payload for %s", permaslug)
   }
   latest := make(map[string]string) // endpoint id -> day of the value kept
   throughput := make(map[string]float64)
   for _, p := range *resp.Data {
      for id, tps := range p.Y {
         if p.X >= latest[id] { // ties keep the later entry
            throughput[id] = tps
            latest[id] = p.X
         }
      }
   }
   if len(throughput) == 0 {
      return nil, errNoThroughput
   }
   return throughput, nil
}

// ---------------------------------------------------------------------------
// Transport and per-model stats endpoints
// ---------------------------------------------------------------------------

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

// skippable reports whether err means "no data for this candidate" — the
// candidate is dropped and the run continues — rather than a real failure.
func skippable(err error) bool {
   return errors.Is(err, errNoScores) ||
      errors.Is(err, errNoGPQA) ||
      errors.Is(err, errNoThroughput)
}

// ---------------------------------------------------------------------------
// Scores: one per-permaslug request -> AutoExacto entries
// ---------------------------------------------------------------------------

// scoreEntry is one entry of the benchmark-scores array (confirmed by
// capture). endpoint_id is null for the auto-routing pseudo-provider and
// decodes to the empty string.
type scoreEntry struct {
   ProviderName  string  `json:"provider_name"`
   BenchmarkType string  `json:"benchmark_type"`
   Score         float64 `json:"score"`
   RunCount      int     `json:"run_count"`
   EndpointID    string  `json:"endpoint_id"`
}

// fetchScores returns one permaslug's AutoExacto score entries, all
// benchmark types. The request is made once, and every real failure
// (transport, HTTP status, decoding, a payload without a data object)
// aborts the run; a 200 that simply carries no scores returns errNoScores,
// which the caller treats as a skip.
func fetchScores(c *http.Client, permaslug string) ([]scoreEntry, error) {
   body, err := httpGet(c, fmt.Sprintf(scoresURLTemplate, url.PathEscape(permaslug)))
   if err != nil {
      return nil, err
   }
   var resp scoresResponse
   if err := json.Unmarshal(body, &resp); err != nil {
      return nil, fmt.Errorf("decoding benchmark scores: %w", err)
   }
   if resp.Data == nil {
      return nil, fmt.Errorf("no data object in benchmark scores payload for %s", permaslug)
   }
   if len(resp.Data.Scores) == 0 {
      return nil, errNoScores
   }
   return resp.Data.Scores, nil
}

// scoresResponse is the benchmark-scores payload. It carries every
// benchmark type for the permaslug (gpqa_diamond and
// tau_bench_verified_airline both arrive in one response); the caller
// filters.
//
// Data is a pointer so that the two empty-looking payloads stay
// distinguishable: no data object at all is a shape change and an ordinary
// error, while a data object with an empty scores array is the server
// reporting that it has nothing for this permaslug (the tencent case).
type scoresResponse struct {
   Data *struct {
      Scores []scoreEntry `json:"scores"`
   } `json:"data"`
}

// ---------------------------------------------------------------------------
// Throughput: one per-permaslug request -> tokens/sec per endpoint
// ---------------------------------------------------------------------------

// throughputPoint is one day of the series. x is the day, kept as a string
// so the latest point is picked by date rather than by payload order (the
// observed payload is ascending, but nothing documents that).
type throughputPoint struct {
   X string             `json:"x"`
   Y map[string]float64 `json:"y"`
}

// throughputResponse is the throughput-comparison payload: a daily series,
// one point per day, each point's y mapping endpoint id -> tokens/sec. Data
// is a pointer so that a payload without a data key at all (a shape change)
// is distinguishable from one carrying an empty series (a model with no
// traffic yet): the former is an error, the latter is not.
type throughputResponse struct {
   Data *[]throughputPoint `json:"data"`
}

// api.go marker - preserve
