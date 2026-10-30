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
// advertises can be picked. "none" is deliberately absent: it means disable, it
// is not a point on this scale, and the catalog cannot be trusted to say which
// models accept it. mistral-large-4-0 lists "none" in supported_efforts and
// still answers 400 "reasoning_effort none is not supported for this model",
// while qwen3.5-plus-02-15 publishes no allowlist at all and accepts "none"
// happily, spending zero reasoning tokens. So "none" is never taken from a list;
// it is sent only to a non-mandatory model that publishes no list, where there
// is nothing better to pick.
var effortRank = map[string]int{
   "minimal": 0,
   "low":     1,
   "medium":  2,
   "high":    3,
   "xhigh":   4,
   "max":     5,
}

// selectModels keeps models added since `since` with base ids only, and returns
// every rejected id with its reason. Exactly one reason is assigned per id, in
// this order: old, variant, router, alias, latest.
//
// Neither modality nor context is tested here. The catalog is queried without a
// modality filter, and no local check replaces it, so non-text models (image,
// audio, video, embeddings) reach the probe list and are probed like any other;
// they will mostly fail and be recorded as errors. The context floor is applied
// only by fetchModels, as the catalog's context=<minContext> query parameter, so
// a model below the floor never arrives and its context_length is not read at
// all; if that parameter is ever ignored or renamed, undersized models are
// probed with no local check to catch them.
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
// length and modalities instead of anything of its own, so it reads as a
// duplicate of the real model listed beside it. The response names the resolved
// model, never the alias. Only the leading ~ is tested: it is the documented
// marker, so no extra catalog field is read, and an alias whose family has no
// in-window concrete model is simply not probed.
//
// The latest case covers the same kind of moving target without the tilde.
// openai/gpt-chat-latest is OpenAI's own alias for whatever its current Instant
// chat model happens to be, so a recorded answer identifies nothing. It is not
// caught above: no ~ prefix, no colon, not under openrouter/, and unlike the
// tilde rows it carries no alias_target field at all, so the catalog does not
// mark it as an alias in any machine-readable way. The -latest suffix is the
// only distinguishing feature it exposes. This runs after the tilde test, so it
// never re-reports an id the alias case already claimed.
//
// A blank id is not filtered here either. The catalog does not return one, so the
// check only ever fired zero times, and an id that somehow arrived blank would
// fall through every case to the default branch and be probed and recorded like
// any other model.
func selectModels(all []modelInfo, since time.Time) (models []modelInfo, skips []excluded) {
   cutoff := since.Unix()

   for _, m := range all {
      id := strings.TrimSpace(m.ID)
      switch {
      case m.Created < cutoff:
         skips = append(skips, excluded{id, "old"})
      case strings.Contains(id, ":"):
         skips = append(skips, excluded{id, "variant"})
      case strings.HasPrefix(id, "openrouter/"):
         skips = append(skips, excluded{id, "router"})
      case strings.HasPrefix(id, "~"):
         skips = append(skips, excluded{id, "alias"})
      case strings.HasSuffix(id, "-latest"):
         skips = append(skips, excluded{id, "latest"})
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
// it was rejected. selectModels returns these so main can count rejections per
// reason; the ids themselves are not logged, only the per-filter totals.
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

// modelInfo carries the fields used for selection and for building the reasoning
// object. The catalog omits Reasoning entirely for non-reasoning models and
// dynamic routers, so a nil pointer means "do not send the field". Neither
// context_length, the architecture modalities nor top_provider are decoded:
// context is enforced solely by the catalog's context= query parameter, nothing
// here tests modalities, and the request sends no max_tokens at all.
type modelInfo struct {
   ID        string `json:"id"`
   Created   int64  `json:"created"`
   Reasoning *struct {
      // Mandatory means reasoning cannot be disabled, so the only thing that
      // can be asked for is a lower amount. When it is false, reasoning can be
      // switched off outright.
      Mandatory bool `json:"mandatory"`
      // Pointer, because absent and false mean different things. false says
      // reasoning is already off when the field is omitted, so the field stays
      // omitted: sending an effort would switch reasoning on, the opposite of
      // what this program wants. Absent says nothing about the default.
      DefaultEnabled *bool `json:"default_enabled"`
      // RawMessage, not []string: absent (field omitted, model exposes no
      // effort selection) and null (no allowlist, every effort accepted) both
      // decode to a nil slice but mean different things. Only an explicit list
      // is read, and only as a preference, because the list is not accurate:
      // it is missing "none" for models that accept it and present for models
      // that reject it.
      SupportedEfforts json.RawMessage `json:"supported_efforts"`
   } `json:"reasoning"`
}

// fetchModels asks the catalog for models at or above minContext and returns
// what it sends. context=<minContext> is the catalog's minimum-context filter
// ("models with smaller context are excluded"), so small models are dropped
// before the response is ever sent. It is the only context filter in the
// program: selectModels does not re-check the floor. Nothing is filtered by
// modality here either, so every modality comes back and is probed.
func fetchModels(client *http.Client, key string) ([]modelInfo, error) {
   url := fmt.Sprintf("%s/models?context=%d", apiBase, minContext)
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

// lowestEffort returns the cheapest effort the model lists, ignoring "none", or
// "" if it lists no ranked value at all. The list arrives in descending order,
// so the whole list is scanned rather than the first element taken, and anything
// effortRank does not know is skipped. For meta/muse-spark-open (a mandatory
// reasoner whose list is ["xhigh","high","medium","low"]) this yields "low",
// which is the least thinking that model will accept.
func (m modelInfo) lowestEffort() string {
   raw := strings.TrimSpace(string(m.Reasoning.SupportedEfforts))
   if raw == "" || raw == "null" {
      return ""
   }
   var listed []string
   if json.Unmarshal(m.Reasoning.SupportedEfforts, &listed) != nil {
      return ""
   }
   best := ""
   for _, e := range listed {
      e = strings.ToLower(strings.TrimSpace(e))
      rank, ok := effortRank[e]
      if ok && (best == "" || rank < effortRank[best]) {
         best = e
      }
   }
   return best
}

// reasoningSpec builds the reasoning object for this model, asking for the least
// reasoning the model will accept:
//
//   no reasoning object          -> no field
//   default_enabled: false       -> no field  (already off, do not switch it on)
//   allowlist has a ranked value -> {"enabled":true,"effort":<lowest ranked>}
//   else, mandatory: false       -> {"enabled":true,"effort":"none"}
//   else, mandatory: true        -> no field  (cannot disable, nothing to pick)
//
// "none" is what actually stops the thinking, and it is never taken from the
// allowlist: mistral-large-4-0 lists it and rejects it with a 400, so a listed
// "none" is skipped in favour of the lowest real value beside it. It is sent
// only when no ranked value exists and the model says reasoning can be disabled
// (mandatory:false) — which is exactly the shape qwen3.5-plus-02-15 has, no
// supported_efforts at all, and that model answered with 0 reasoning tokens
// instead of spending the entire token budget thinking.
//
// A model with no ranked value that must reason is left alone rather than
// guessed at: omitting the field leaves the provider's own default in place,
// which always works, and an invented effort can 400.
//
// What this function cannot do: for a mandatory-reasoning model with an
// allowlist, "lowest ranked" is the floor, and it is a hint rather than a bound.
// muse-spark-open at "low" still produced 43,938 characters of reasoning on a
// real task. This function is all the economising that happens; the request
// imposes no output limit, so such a model is allowed to finish instead of being
// cut off mid-thought.
//
// enabled is always sent as true alongside the effort, matching the request
// shape verified working; enabled:false is never sent, because it is rewritten
// upstream to effort "none" and fails on the models that reject that.
func (m modelInfo) reasoningSpec() *reasoning {
   if m.Reasoning == nil {
      return nil
   }
   if m.Reasoning.DefaultEnabled != nil && !*m.Reasoning.DefaultEnabled {
      return nil
   }
   on := true
   if best := m.lowestEffort(); best != "" {
      return &reasoning{Enabled: &on, Effort: best}
   }
   if !m.Reasoning.Mandatory {
      return &reasoning{Enabled: &on, Effort: "none"}
   }
   return nil
}

// catalog.go marker preserve
