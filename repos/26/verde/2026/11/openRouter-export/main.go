// main.go — extract-text: read an OpenRouter export, unnest the first message,
// drop reasoning parts, remove the largest remaining messages, write flat output.
//
// The rules, in order:
//  1. Unpack the first message if it carries a previous run's output.
//  2. The very first and the very last message are never removed.
//  3. Drop reasoning parts from every message, shielded ones included - a user
//     message should carry none, so this is a no-op there; if it isn't, we say so.
//  4. Remove the N largest of the remaining messages. Never the shielded two.
package main

import (
   "bytes"
   "encoding/json"
   "flag"
   "fmt"
   "os"
   "sort"
   "strconv"
   "strings"
   "unicode/utf8"
)

// commas groups a non-negative integer with thousands separators.
func commas(n int) string {
   s := strconv.Itoa(n)
   var b strings.Builder
   for i, c := range s {
      if i > 0 && (len(s)-i)%3 == 0 {
         b.WriteByte(',')
      }
      b.WriteRune(c)
   }
   return b.String()
}

// isReasoningPart reports whether a part's type marks it as chain-of-thought:
// reasoning, reasoning_text, reasoning.text, reasoning.summary, thinking, ...
// Matching is by substring so provider-specific spellings are all caught, and
// it can never fire on an absent type or on plain "text"/"input_text".
func isReasoningPart(p textPart) bool {
   t := strings.ToLower(strings.TrimSpace(p.Type))
   return t != "" && (strings.Contains(t, "reason") || strings.Contains(t, "think"))
}

// itemRole reports the role an item declared, e.g. "user". Empty when the item
// carries no data object or no role. Used only to check the assumption that the
// first and last messages are user turns; it never affects what is kept.
func itemRole(raw json.RawMessage) string {
   var probe struct {
      Data *struct {
         Role string `json:"role"`
      } `json:"data"`
   }
   if err := json.Unmarshal(raw, &probe); err != nil || probe.Data == nil {
      return ""
   }
   return probe.Data.Role
}

func main() {
   inPath := flag.String("i", "", "input JSON file path (an OpenRouter export)")
   outPath := flag.String("o", "", "output JSON file path (compacted array of {type,text} objects)")
   removeN := flag.Int("r", 0,
      "number of largest messages to remove, counted after unnesting and after reasoning is dropped; the first and the last message are always kept")
   flag.Parse()

   if *inPath == "" || *outPath == "" {
      fmt.Fprintln(os.Stderr, "usage: extract-text -i <input.json> -o <output.json> [-r N]")
      flag.PrintDefaults()
      os.Exit(1)
   }
   if *removeN < 0 {
      fmt.Fprintln(os.Stderr, "error: -r must be zero or positive")
      os.Exit(1)
   }

   if err := run(*inPath, *outPath, *removeN); err != nil {
      fmt.Fprintf(os.Stderr, "error: %v\n", err)
      os.Exit(1)
   }
}

// partLabel names one text object for reporting.
func partLabel(p textPart) string {
   if p.Type == "" {
      return "text"
   }
   return p.Type
}

// partSize is the encoded size of one {type,text} object, i.e. what it costs in
// the output.
func partSize(p textPart) int {
   var buf bytes.Buffer
   enc := json.NewEncoder(&buf)
   enc.SetEscapeHTML(false)
   if err := enc.Encode(p); err != nil {
      return len(p.Text)
   }
   return buf.Len() - 1 // drop the trailing newline
}

// partsSize is what a set of parts costs in the output.
func partsSize(ps []textPart) int {
   n := 0
   for _, p := range ps {
      n += partSize(p)
   }
   return n
}

// preview collapses whitespace and truncates to at most n runes for reporting.
func preview(s string, n int) string {
   s = strings.Join(strings.Fields(s), " ")
   if utf8.RuneCountInString(s) > n {
      s = string([]rune(s)[:n]) + "…"
   }
   return s
}

func run(inPath, outPath string, removeN int) error {
   raw, err := os.ReadFile(inPath)
   if err != nil {
      return fmt.Errorf("reading input: %w", err)
   }

   var root map[string]json.RawMessage
   if err := json.Unmarshal(raw, &root); err != nil {
      return fmt.Errorf("parsing JSON: %w", err)
   }

   itemsRaw, ok := root["items"]
   if !ok {
      return fmt.Errorf(`no "items" object found in input JSON`)
   }
   items, err := readItems(itemsRaw)
   if err != nil {
      return err
   }
   if len(items) == 0 {
      return fmt.Errorf(`"items" object is empty`)
   }
   fmt.Printf("Input: %d items, %s\n", len(items), humanSize(len(raw)))

   // Step 1: unnest the first message. Any part of it that is a previous run's
   // output is expanded into the messages it holds, in place, so the first
   // element of the result is the original chat's first message.
   firstPs, err := textParts(items[0].Val)
   if err != nil {
      return fmt.Errorf("extracting text from item %q: %w", items[0].Key, err)
   }
   flat, nested := unnestFirst(firstPs)

   msgs := make([]msg, 0, len(items)+len(flat))

   if len(flat) == 0 {
      fmt.Printf("First message %s [%s]: no text\n", items[0].Key, itemLabel(items[0].Val))
   } else {
      fmt.Printf("First message %s [%s]: %d text part(s)\n",
         items[0].Key, itemLabel(items[0].Val), len(flat))
      if nested {
         fmt.Printf("  it holds the output of a previous run: %d text object(s) inside\n", len(flat))
      }
      fmt.Printf("  original prompt: %q\n", preview(flat[0].Text, 70))
      for i, p := range flat {
         key := items[0].Key
         if i > 0 {
            key = fmt.Sprintf("%s:inner[%d]", items[0].Key, i)
         }
         m := msg{key: key, label: partLabel(p), parts: []textPart{p}}
         if i == 0 {
            // The original prompt answers in its item's role; the messages
            // unpacked out of a previous run carry their own history and are
            // not re-typed here.
            m.role = itemRole(items[0].Val)
         }
         msgs = append(msgs, m)
      }
   }

   for _, it := range items[1:] {
      ps, err := textParts(it.Val)
      if err != nil {
         return fmt.Errorf("extracting text from item %q: %w", it.Key, err)
      }
      msgs = append(msgs, msg{
         key:   it.Key,
         label: itemLabel(it.Val),
         role:  itemRole(it.Val),
         parts: ps,
      })
   }

   // Messages with no text carry nothing. Drop them before naming the first and
   // the last, so an empty trailing item cannot steal the shield.
   nonEmpty := make([]msg, 0, len(msgs))
   for _, m := range msgs {
      if len(m.parts) > 0 {
         nonEmpty = append(nonEmpty, m)
      }
   }
   msgs = nonEmpty
   if len(msgs) == 0 {
      return fmt.Errorf("no text found in any item")
   }
   fmt.Printf("Messages: %d top-level item(s) -> %d message(s) with text\n", len(items), len(msgs))

   // Step 2: the very first and the very last message are never removed. That is
   // all protection means; the reasoning rule below still applies to them, and
   // since they should be user turns there should be nothing to drop. Warn if
   // that assumption does not hold, because that is worth knowing.
   msgs[0].protected, msgs[0].why = true, "first"
   if len(msgs) == 1 {
      msgs[0].why = "first and last"
   } else {
      msgs[len(msgs)-1].protected, msgs[len(msgs)-1].why = true, "last"
   }
   shielded := []msg{msgs[0]}
   if len(msgs) > 1 {
      shielded = append(shielded, msgs[len(msgs)-1])
   }
   for _, m := range shielded {
      if m.role != "" && !strings.EqualFold(m.role, "user") {
         fmt.Printf("  warning: %s message %s [%s] has role %q, not \"user\"\n",
            m.why, m.key, m.label, m.role)
      }
   }

   // Step 3: drop reasoning from every message, shielded or not. The part is the
   // unit, so a message mixing reasoning and content keeps the content and is
   // dropped only once empty.
   rParts, rBytes := 0, 0
   kept := make([]msg, 0, len(msgs))
   for _, m := range msgs {
      var n, b int
      m.parts, n, b = pruneParts(m.parts)
      rParts += n
      rBytes += b
      if len(m.parts) == 0 && !m.protected {
         // Everything in it was reasoning; the message goes away whole.
         continue
      }
      if len(m.parts) == 0 {
         // Only reachable if a shielded message were typed entirely as
         // reasoning. The shield outranks pruning: it stays, empty.
         fmt.Printf("  note: %s message %s was entirely reasoning; kept anyway\n", m.why, m.key)
      }
      m.size = partsSize(m.parts)
      kept = append(kept, m)
   }
   if rParts == 0 {
      fmt.Println("Reasoning parts removed: none")
   } else {
      fmt.Printf("Reasoning parts removed: %s, %s\n", commas(rParts), humanSize(rBytes))
   }

   // Step 4: remove the largest remaining messages. Sizes are post-reasoning, so
   // a message cannot be dropped for bytes that are no longer there. The first
   // and the last message are never candidates.
   if removeN > 0 {
      cand := make([]int, 0, len(kept))
      for i, m := range kept {
         if !m.protected {
            cand = append(cand, i)
         }
      }
      if removeN > len(cand) {
         return fmt.Errorf("-r %d exceeds the %d removable message(s); the first and the last message are always kept",
            removeN, len(cand))
      }
      sort.SliceStable(cand, func(a, b int) bool {
         return kept[cand[a]].size > kept[cand[b]].size
      })
      drop := make(map[int]bool, removeN)
      fmt.Printf("Removing %d largest message(s):\n", removeN)
      for _, i := range cand[:removeN] {
         drop[i] = true
         fmt.Printf("  - %s [%s]: %s\n", kept[i].key, kept[i].label, humanSize(kept[i].size))
      }
      live := make([]msg, 0, len(kept)-removeN)
      for i, m := range kept {
         if !drop[i] {
            live = append(live, m)
         }
      }
      kept = live
   } else {
      fmt.Println("Nothing else removed (-r 0)")
   }
   fmt.Printf("Kept %d of %d message(s)\n", len(kept), len(msgs))
   if len(kept) == 1 {
      fmt.Printf("  shielded: %s [%s] (%s)\n", kept[0].key, kept[0].label, kept[0].why)
   } else {
      fmt.Printf("  shielded: %s [%s] (%s) ... %s [%s] (%s)\n",
         kept[0].key, kept[0].label, kept[0].why,
         kept[len(kept)-1].key, kept[len(kept)-1].label, kept[len(kept)-1].why)
   }

   // Write flat output.
   out := make([]textPart, 0, len(kept))
   for _, m := range kept {
      out = append(out, m.parts...)
   }

   var buf bytes.Buffer
   enc := json.NewEncoder(&buf)
   enc.SetEscapeHTML(false) // keep <, >, & as-is instead of \u003c etc.
   if err := enc.Encode(out); err != nil {
      return fmt.Errorf("marshaling final output: %w", err)
   }
   finalBytes := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))

   if err := os.WriteFile(outPath, finalBytes, 0o644); err != nil {
      return fmt.Errorf("writing output: %w", err)
   }

   tokens := 0
   for _, p := range out {
      tokens += tokenEstimate(p.Text)
   }
   fmt.Printf("Output: %d text object(s) from %d message(s), %s, ~%s tokens (est.)\n",
      len(out), len(kept), humanSize(len(finalBytes)), commas(tokens))
   fmt.Printf("Wrote %s\n", outPath)
   return nil
}

// tokenEstimate approximates a token count without a tokenizer: each run of
// ASCII non-space characters costs one token per four runes, and each non-ASCII
// rune costs one token on its own. Whitespace is free, since token boundaries
// fall there. Expect it to land within roughly 10-20% of a real BPE tokenizer.
func tokenEstimate(s string) int {
   n, run := 0, 0
   flush := func() {
      if run > 0 {
         n += (run + 3) / 4
         run = 0
      }
   }
   for _, r := range s {
      switch {
      case r == ' ' || r == '\t' || r == '\n' || r == '\r':
         flush()
      case r < 0x80:
         run++
      default:
         flush()
         n++
      }
   }
   flush()
   return n
}

// pruneParts drops reasoning parts, reporting how many were dropped and how many
// bytes they cost.
func pruneParts(ps []textPart) (kept []textPart, dropped, droppedBytes int) {
   kept = make([]textPart, 0, len(ps))
   for _, p := range ps {
      if isReasoningPart(p) {
         dropped++
         droppedBytes += partSize(p)
         continue
      }
      kept = append(kept, p)
   }
   return kept, dropped, droppedBytes
}

// unnestFirst expands every part of the first message that is a previous run's
// output into the messages it holds, in place. Nothing is reordered, so the
// first element of the result is the original chat's first message. Output is
// always flat, so one pass is enough - no recursion. splitExport itself handles
// JSON string quoting and surrounding code fences.
func unnestFirst(ps []textPart) (flat []textPart, nested bool) {
   flat = make([]textPart, 0, len(ps)+8)
   for _, p := range ps {
      msgs, ok := splitExport(p.Text)
      if !ok {
         flat = append(flat, p)
         continue
      }
      nested = true
      flat = append(flat, msgs...)
   }
   return flat, nested
}

// msg is one message. It is the unit -r ranks and removes; reasoning is dropped
// part by part inside it first.
type msg struct {
   key       string // item key, or "<item>:inner[n]" for a message found inside the first
   label     string // e.g. "message/user"
   role      string // "user", "assistant", ... when the source carried one
   parts     []textPart
   size      int    // encoded size of parts, set once reasoning is gone
   protected bool   // the very first or the very last message: never removed
   why       string // "first", "last", or "first and last"
}

// orderedItem is one member of the top-level "items" object, in document order.
type orderedItem struct {
   Key string
   Val json.RawMessage
}

// readItems stream-decodes the "items" object so member order survives.
func readItems(itemsRaw json.RawMessage) ([]orderedItem, error) {
   dec := json.NewDecoder(bytes.NewReader(itemsRaw))

   tok, err := dec.Token()
   if err != nil {
      return nil, fmt.Errorf("parsing items object: %w", err)
   }
   if d, ok := tok.(json.Delim); !ok || d != '{' {
      return nil, fmt.Errorf(`"items" is not a JSON object`)
   }

   items := make([]orderedItem, 0)
   for dec.More() {
      keyTok, err := dec.Token()
      if err != nil {
         return nil, fmt.Errorf("parsing items object: %w", err)
      }
      key, ok := keyTok.(string)
      if !ok {
         return nil, fmt.Errorf("unexpected token in items object: expected key string, got %v", keyTok)
      }

      var val json.RawMessage
      if err := dec.Decode(&val); err != nil {
         return nil, fmt.Errorf("parsing item %q: %w", key, err)
      }
      items = append(items, orderedItem{Key: key, Val: val})
   }
   if _, err := dec.Token(); err != nil { // closing '}'
      return nil, fmt.Errorf("parsing items object: %w", err)
   }
   return items, nil
}

// end main.go
