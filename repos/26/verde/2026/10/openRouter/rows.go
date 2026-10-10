// rows.go marker preserve
package main

import (
   "net/http"
   "slices"
)

// ---------------------------------------------------------------------------
// Working types: a candidate and its per-provider row
// ---------------------------------------------------------------------------

// candidate is one open-weights permaslug selected from the catalog, the
// key for both stats requests.
type candidate struct {
   slug string
   // contextLength is the model card's window, echoed in the per-candidate
   // block so the floor's effect is visible per candidate.
   contextLength int
}

// providerGPQA aggregates one provider's GPQA entries: every
// gpqa_diamond score plus every endpoint id the provider was scored on.
// Both row dimensions — the GPQA score and the throughput — are reduced by
// the same rule: the median over the provider's scored endpoints.
type providerGPQA struct {
   Scores      []float64
   EndpointIDs []string
}

// row is one model + one provider: the flat unit of output.
type row struct {
   Model    string
   Provider string
   // GPQA is the median of the provider's AutoExacto GPQA Diamond
   // scores across its scored endpoints, 0..1.
   GPQA float64
   // Throughput is the median of the provider's endpoints' throughput,
   // tokens/sec.
   Throughput float64
}

// ---------------------------------------------------------------------------
// Rows: one permaslug -> one row per provider
// ---------------------------------------------------------------------------

// fetchRows returns one row per provider: provider, GPQA Diamond score,
// and median throughput, from two per-permaslug stats requests — no model
// page, no HTML. A row is emitted only when the provider has both a GPQA
// score and a throughput measurement. Both the score and the throughput
// are the median over the provider's scored endpoints — one reduction rule
// for both dimensions.
//
// scoredProviders is the number of providers that have a gpqa_diamond score
// for this model, whether or not each ends up with a row. The caller logs it
// beside len(rows), so a candidate that is scored on GPQA but produces
// nothing says why instead of printing a bare zero. It is 0 whenever err is
// non-nil.
//
// A candidate whose stats are simply absent comes back with a skippable
// sentinel; every other failure (transport, HTTP status, decoding) is an
// ordinary error. The throughput request is not made when the scores are
// already absent.
func fetchRows(c *http.Client, cd *candidate) (rows []*row, scoredProviders int, err error) {
   scores, err := fetchScores(c, cd.slug)
   if err != nil {
      return nil, 0, err
   }
   // Endpoint id -> tokens/sec, same uuid namespace as the scores'
   // endpoint_id, so the join below is exact.
   throughputByEndpoint, err := fetchThroughput(c, cd.slug)
   if err != nil {
      return nil, 0, err
   }
   return rowsFromScores(cd, scores, throughputByEndpoint)
}

// rowsFromScores reduces one permaslug's benchmark scores and its
// per-endpoint throughput to rows, one per provider, and reports how many
// providers carried a gpqa_diamond score at all. Scores that carry no
// gpqa_diamond entries (tau data only, say) come back with a skippable
// sentinel.
//
// A provider with a GPQA score whose endpoint has no throughput entry is
// dropped from rows but still counted in scoredProviders. Returning both is
// what lets the caller print "0 ranked of 16 scored" rather than "0 rows".
func rowsFromScores(cd *candidate, scores []scoreEntry, throughputByEndpoint map[string]float64) (rows []*row, scoredProviders int, err error) {
   // GPQA Diamond per provider. A provider can have several scored
   // endpoints (e.g. different quantizations); every score is kept, and
   // all of the provider's endpoint ids are collected for the tps join.
   // The auto-routing pseudo-provider is included: it has a score but a null
   // endpoint id, so it is always counted and never ranked.
   gpqaByProvider := make(map[string]providerGPQA)
   for _, s := range scores {
      if s.BenchmarkType != "gpqa_diamond" {
         continue
      }
      g := gpqaByProvider[s.ProviderName]
      g.Scores = append(g.Scores, s.Score)
      if s.EndpointID != "" && !slices.Contains(g.EndpointIDs, s.EndpointID) {
         g.EndpointIDs = append(g.EndpointIDs, s.EndpointID)
      }
      gpqaByProvider[s.ProviderName] = g
   }
   if len(gpqaByProvider) == 0 {
      return nil, 0, errNoGPQA
   }

   rows = make([]*row, 0, len(gpqaByProvider))
   for provider, g := range gpqaByProvider {
      // Same reduction for both dimensions: the median over the
      // provider's scored endpoints.
      var throughputs []float64
      for _, id := range g.EndpointIDs {
         if tp, ok := throughputByEndpoint[id]; ok {
            throughputs = append(throughputs, tp)
         }
      }
      if len(throughputs) == 0 {
         continue // no throughput for this provider -> no row
      }
      slices.Sort(g.Scores)
      slices.Sort(throughputs)
      rows = append(rows, &row{
         Model:      cd.slug,
         Provider:   provider,
         GPQA:       percentile(g.Scores, 50),
         Throughput: percentile(throughputs, 50),
      })
   }
   return rows, len(gpqaByProvider), nil
}

// rows.go marker preserve
