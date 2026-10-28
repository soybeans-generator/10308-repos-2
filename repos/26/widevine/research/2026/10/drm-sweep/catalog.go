// catalog.go marker preserve
package main

import (
   "encoding/json"
   "fmt"
   "io"
   "log"
   "net/http"
   "slices"
   "strings"
   "time"
)

// effortRank orders effort levels low to high so the cheapest one a model
// advertises can be picked. "none" is deliberately absent: it means disable,
// and a mandatory-reasoning model rejects it.
var effortRank = map[string]int{
   "minimal": 0,
   "low":     1,
   "medium":  2,
   "high":    3,
   "xhigh":   4,
   "max":     5,
}

func isTextModel(m modelInfo) bool {
   text := func(xs []string) bool {
      return len(xs) == 0 || slices.ContainsFunc(xs, func(x string) bool {
         return strings.EqualFold(strings.TrimSpace(x), "text")
      })
   }
   return text(m.Architecture.Input) && text(m.Architecture.Output)
}

// selectModels keeps text-in/text-out models added since `since`, with base ids
// only and a context window of at least minContext, and returns every rejected
// id with its reason. Exactly one reason is assigned per id, in this order:
// empty-id, old, small-context, non-text, variant, router, alias.
//
// The small-context case is a backstop: fetchModels already asks the catalog for
// context>=minContext, so a model that is too small normally never arrives.
// Checking context_length here keeps the floor true if the query parameter is
// ignored or renamed, and a missing context_length (0) reads as too small, the
// same way a missing created reads as old.
//
// Anything carrying a variant suffix (:free, :nitro, :floor, :online, :thinking,
// :extended, :batch) is dropped, because those are API-side routing and feature
// switches, not separate models. Every openrouter/* id is dropped too: those are
// routers and server-tool aliases (auto, fusion, fusion-flash, pareto-code, ...),
// not models. Fusion alone fans out to a panel plus an analyst with web search,
// and they report the concrete model in the response rather than the alias, so a
// row would identify nothing. A missing created (0) reads as ancient and is
// dropped as old. No open-weight requirement is applied.
//
// Every ~author/family-latest id is dropped as an alias for the same reason, and
// it needs its own check: the tilde is a prefix, not a suffix, so the colon test
// above never sees it. Such a slug resolves to whichever concrete model in the
// family is newest, and its catalog row reports that target's pricing, context
// length and modalities instead of anything of its own, so it clears the window,
// context and text checks and reads as a duplicate of the real model listed
// beside it. The response names the resolved model, never the alias. Only the
// leading ~ is tested: it is the documented marker, so no extra catalog field is
// read, and an alias whose family has no in-window concrete model is simply not
// probed.
func selectModels(all []modelInfo, since time.Time) (models []modelInfo, skips []excluded) {
   cutoff := since.Unix()

   for _, m := range all {
      id := strings.TrimSpace(m.ID)
      switch {
      case id == "":
         skips = append(skips, excluded{"<empty id>", "empty-id"})
      case m.Created < cutoff:
         skips = append(skips, excluded{id, "old"})
      case m.ContextLength < minContext:
         skips = append(skips, excluded{id, "small-context"})
      case !isTextModel(m):
         skips = append(skips, excluded{id, "non-text"})
      case strings.Contains(id, ":"):
         skips = append(skips, excluded{id, "variant"})
      case strings.HasPrefix(id, "openrouter/"):
         skips = append(skips, excluded{id, "router"})
      case strings.HasPrefix(id, "~"):
         skips = append(skips, excluded{id, "alias"})
      default:
         models = append(models, m)
      }
   }

   slices.SortFunc(models, func(a, b modelInfo) int { return strings.Compare(a.ID, b.ID) })
   slices.SortFunc(skips, func(a, b excluded) int {
      if c := strings.Compare(a.Reason, b.Reason); c != 0 {
         return c
      }
      return strings.Compare(a.ID, b.ID)
   })
   return models, skips
}

// excluded is one catalog id that will not be probed, with the single reason
// it was rejected. selectModels returns these so main can print the full list.
type excluded struct {
   ID     string
   Reason string
}

// loggingTransport logs every outbound request before it is sent. Every client
// in this program uses it, so the log is the complete list of HTTP requests:
// one GET for the model catalog, then one POST per model probed. A request
// appearing twice means it was sent twice.
type loggingTransport struct{}

func (loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
   log.Println(req.Method, req.URL)
   return http.DefaultTransport.RoundTrip(req)
}

// modelInfo carries the fields used for selection and for building the
// reasoning object. The catalog omits Reasoning entirely for non-reasoning
// models and dynamic routers, so a nil pointer means "do not send the field".
type modelInfo struct {
   ID string `json:"id"`
   // ContextLength is the model's total window in tokens. Null or absent
   // decodes to 0, which selectModels treats as smaller than minContext.
   ContextLength int   `json:"context_length"`
   Created       int64 `json:"created"`
   Reasoning     *struct {
      // Mandatory means reasoning cannot be disabled and effort "none" is
      // rejected: the model must reason, so only the amount is negotiable.
      Mandatory bool `json:"mandatory"`
      // RawMessage, not []string: absent (field omitted, model exposes no
      // effort selection) and null (no allowlist, every effort accepted) both
      // decode to a nil slice but mean different things.
      SupportedEfforts json.RawMessage `json:"supported_efforts"`
   } `json:"reasoning"`
   Architecture struct {
      Input  []string `json:"input_modalities"`
      Output []string `json:"output_modalities"`
   } `json:"architecture"`
}

func fetchModels(client *http.Client, key string) ([]modelInfo, error) {
   // context=<minContext> is the catalog's minimum-context filter ("models with
   // smaller context are excluded"), so small models are dropped before the
   // response is ever sent.
   url := fmt.Sprintf("%s/models?output_modalities=text&context=%d", apiBase, minContext)
   hr, err := http.NewRequest(http.MethodGet, url, nil)
   if err != nil {
      return nil, err
   }
   hr.Header.Set("Authorization", "Bearer "+key)
   hr.Header.Set("Accept", "application/json")

   resp, err := client.Do(hr)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
   if resp.StatusCode != http.StatusOK {
      return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(raw), 200))
   }

   var env struct {
      Data []modelInfo `json:"data"`
   }
   if err := json.Unmarshal(raw, &env); err != nil {
      return nil, fmt.Errorf("decode: %w", err)
   }
   return env.Data, nil
}

// reasoningSpec builds the reasoning object for this model. Disable reasoning
// outright whenever the model allows it, and ask for the lowest effort the
// model advertises when it does not:
//
//   no reasoning object          -> no field
//   mandatory:false              -> enabled:false (off)
//   mandatory, efforts listed    -> lowest of them, ignoring "none"
//   mandatory, supported:null    -> minimal (every effort accepted)
//   mandatory, field omitted     -> minimal (no effort selection to respect)
//
// effort:"none" is never sent. It means disable, which a mandatory-reasoning
// model rejects with a 400, and it is absent from the allowlist of most
// optional models too, so it risks a 400 where enabled:false does not.
func (m modelInfo) reasoningSpec() *reasoning {
   if m.Reasoning == nil {
      return nil
   }
   if !m.Reasoning.Mandatory {
      off := false
      return &reasoning{Enabled: &off}
   }

   // The list arrives in descending order, so scan for the minimum rather
   // than taking the first element.
   if raw := strings.TrimSpace(string(m.Reasoning.SupportedEfforts)); raw != "" && raw != "null" {
      var listed []string
      if json.Unmarshal(m.Reasoning.SupportedEfforts, &listed) == nil {
         best := ""
         for _, e := range listed {
            e = strings.ToLower(strings.TrimSpace(e))
            rank, ok := effortRank[e]
            if ok && (best == "" || rank < effortRank[best]) {
               best = e
            }
         }
         if best != "" {
            return &reasoning{Effort: best}
         }
      }
   }
   return &reasoning{Effort: "minimal"}
}

// catalog.go marker preserve
