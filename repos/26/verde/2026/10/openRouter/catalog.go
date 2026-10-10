// catalog.go marker preserve
package main

import (
   "encoding/json"
   "fmt"
   "net/http"
   "strings"
)

// ---------------------------------------------------------------------------
// Catalog: single request -> open-weights candidates
// ---------------------------------------------------------------------------

// One request for the whole catalog. The context floor is appended in
// fetchCandidates rather than baked in here, so the logged floor and the
// sent parameter cannot drift apart.
const catalogURL = "https://openrouter.ai/api/frontend/v1/models/find?active=true"

// minContext is the model-context floor in tokens, sent to the catalog as
// the `context` query parameter. Hardcoded for now; it is logged at the
// start of every run so the cutoff is never implicit.
//
// Verified live against this find endpoint (not only against the documented
// /api/v1/models, which documents the same parameter name): with
// context=2000000 the payload holds exactly the five models whose
// context_length is 2000000 and no others, so the parameter is honored and
// the bound is inclusive (>=). The comparison is against the model's own
// context_length, not the served endpoints' (a provider may serve less than
// the model advertises).
const minContext = 1000000

func fetchCandidates(c *http.Client) ([]candidate, catalogStats, error) {
   var st catalogStats
   // The context floor is applied server-side. NB: fetchURL, not url — the
   // url package is imported for PathEscape in the stats helpers in api.go.
   fetchURL := fmt.Sprintf("%s&context=%d", catalogURL, minContext)
   body, err := httpGet(c, fetchURL)
   if err != nil {
      return nil, st, err
   }
   var resp findResponse
   if err := json.Unmarshal(body, &resp); err != nil {
      return nil, st, fmt.Errorf("decoding catalog: %w", err)
   }

   st.AfterContext = len(resp.Data.Models)
   seen := make(map[string]bool)
   var cands []candidate
   for _, m := range resp.Data.Models {
      // Open weights = weights published on Hugging Face. A closed model
      // carries hf_slug as null or as "" — both decode to the empty string,
      // so one check covers them (verified live on both spellings).
      if m.Permaslug == "" || m.HfSlug == "" {
         st.DroppedClosed++
         continue
      }
      // The catalog can contain duplicate entries per permaslug.
      if seen[m.Permaslug] {
         st.DroppedDuplicate++
         continue
      }
      seen[m.Permaslug] = true

      // The permaslug is the key for both stats requests.
      cands = append(cands, candidate{slug: m.Permaslug, contextLength: m.ContextLength})
   }
   return cands, st, nil
}

// filterReport renders the filter chain: which filters ran, which side
// applied each, and how many models each step removed. The cutoff is
// printed from minContext, the same constant the request URL is built
// from, so the logged cutoff cannot drift from the sent one.
//
// The dedupe is not listed as a filter: a duplicate entry is a repeat of
// a permaslug already kept, not a model lost, so a "dropped" row would
// overstate it. It is not hidden either — the candidates line carries
// distinct-of-total, so the repeats stay countable from the report alone
// (open-weight entries minus distinct) and the arithmetic still closes.
func filterReport(st catalogStats) string {
   data := &strings.Builder{}
   fmt.Fprintf(data, "catalog filters, in order:\n")
   fmt.Fprintf(data, "  1. context >= %d tokens   server-side, models/find `context` (model card)\n", minContext)
   fmt.Fprintf(data, "  2. open weights           client-side, hf_slug non-empty\n")
   fmt.Fprintf(data, "\n")
   fmt.Fprintf(data, "  %-33s %6d\n", "after filter 1 (context):", st.AfterContext)
   fmt.Fprintf(data, "  %-33s %6d\n", "dropped by filter 2 (no weights):", st.DroppedClosed)
   openEntries := st.AfterContext - st.DroppedClosed
   fmt.Fprintf(data, "  %-33s %6d of %d entries\n", "candidates (distinct permaslugs):",
      openEntries-st.DroppedDuplicate, openEntries)
   return data.String()
}

type catalogModel struct {
   Permaslug string `json:"permaslug"`
   HfSlug    string `json:"hf_slug"` // empty == not open weights (null or "")
   // ContextLength is the model card's window — the field the context
   // query parameter filters on. Echoed per candidate in the progress block;
   // the model card value, not a per-endpoint limit, which can be lower.
   ContextLength int `json:"context_length"`
}

// catalogStats counts what the catalog filters removed, in the order they
// ran. It exists so the run log can name every filter and its effect
// instead of printing a bare survivor count that looks like the size of
// the whole catalog.
//
// AfterContext is what the server returned for the context filter — already
// filtered, NOT the whole catalog. The two dropped counts are the
// client-side steps, in code order (a model that is both closed and a
// duplicate counts under DroppedClosed, because that check runs first), so
// the fields always sum: AfterContext - DroppedClosed - DroppedDuplicate
// = candidates. The report prints the last step as distinct-of-total on
// the candidates line rather than a "dropped" row, since a duplicate is a
// repeat of a slug already kept, not a model lost.
type catalogStats struct {
   AfterContext     int // models the server returned for context >= minContext
   DroppedClosed    int // of those, dropped for having no Hugging Face weights
   DroppedDuplicate int // of those, entries repeating an earlier permaslug — repeats, not lost models
}

// findResponse carries only the fields this program reads. The payload also
// has a benchmarks map (AA intelligence index and friends) alongside models;
// it is neither decoded nor used, and unknown JSON fields are ignored, so
// nothing needs to name it here.
type findResponse struct {
   Data struct {
      Models []catalogModel `json:"models"`
   } `json:"data"`
}

// catalog.go marker preserve
