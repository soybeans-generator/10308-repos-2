// main.go — extract-text: read an OpenRouter export, unnest the first message, remove, write flat output.
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

func main() {
   inPath := flag.String("i", "", "input JSON file path (an OpenRouter export)")
   outPath := flag.String("o", "", "output JSON file path (compacted array of {type,text} objects)")
   removeCount := flag.Int("r", 0,
      "number of largest messages to remove, counted after unnesting; the original first prompt is always kept")
   flag.Parse()

   if *inPath == "" || *outPath == "" {
      fmt.Fprintln(os.Stderr, "usage: extract-text -i <input.json> -o <output.json> [-r N]")
      flag.PrintDefaults()
      os.Exit(1)
   }

   if err := run(*inPath, *outPath, *removeCount); err != nil {
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

// preview collapses whitespace and truncates to at most n runes for reporting.
func preview(s string, n int) string {
   s = strings.Join(strings.Fields(s), " ")
   if utf8.RuneCountInString(s) > n {
      s = string([]rune(s)[:n]) + "…"
   }
   return s
}

func run(inPath, outPath string, removeCount int) error {
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

   origCompact, err := compact(itemsRaw)
   if err != nil {
      return fmt.Errorf("compacting items object: %w", err)
   }
   fmt.Printf("Original \"items\" object: %d items, size %s\n", len(items), humanSize(len(origCompact)))

   // Step 1: unnest.
   units, err := buildUnits(items)
   if err != nil {
      return err
   }
   fmt.Printf("Messages: %d before unnesting (first message counted as 1) -> %d after unnesting\n",
      len(items), len(units))

   // Step 2: remove, largest first, never the locked prompt. The count is the
   // unnested one.
   if removeCount > 0 {
      cand := make([]int, 0, len(units))
      for i, u := range units {
         if !u.locked {
            cand = append(cand, i)
         }
      }
      if removeCount > len(cand) {
         return fmt.Errorf("-r %d exceeds number of removable messages (%d of %d unnested messages); the original first prompt is always kept",
            removeCount, len(cand), len(units))
      }
      sort.SliceStable(cand, func(a, b int) bool {
         return units[cand[a]].size > units[cand[b]].size
      })

      remove := make(map[int]bool, removeCount)
      fmt.Printf("Removing %d largest removable message(s):\n", removeCount)
      for _, i := range cand[:removeCount] {
         fmt.Printf("  - %s [%s] : %s\n", units[i].key, units[i].label, humanSize(units[i].size))
         remove[i] = true
      }

      kept := make([]unit, 0, len(units)-removeCount)
      for i, u := range units {
         if !remove[i] {
            kept = append(kept, u)
         }
      }
      units = kept
   } else {
      fmt.Printf("Nothing removed (-r 0); all %d message(s) kept\n", len(units))
   }

   // Step 3: write unnested output.
   out := make([]textPart, 0, len(units))
   for _, u := range units {
      out = append(out, u.parts...)
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
   fmt.Printf("Final output: %d text object(s) from %d kept message(s), size %s, ~%s tokens (est.)\n",
      len(out), len(units), humanSize(len(finalBytes)), commas(tokens))
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

// unquote strips JSON string quoting, for output that reached the message
// escaped (e.g. pasted as a quoted string) instead of as raw JSON.
func unquote(s string) string {
   t := strings.TrimSpace(s)
   if len(t) > 1 && t[0] == '"' && t[len(t)-1] == '"' {
      if u, err := strconv.Unquote(t); err == nil {
         return u
      }
   }
   return s
}

// unnestFirst expands every part of the first message that is a previous run's
// output into the messages it holds, in place. Nothing is reordered, so the
// first element of the result is the original chat's first message. Output is
// always flat, so one pass is enough - no recursion.
func unnestFirst(ps []textPart) (flat []textPart, nested bool) {
   flat = make([]textPart, 0, len(ps)+8)
   for _, p := range ps {
      msgs, ok := splitExport(unquote(p.Text))
      if !ok {
         flat = append(flat, p)
         continue
      }
      nested = true
      flat = append(flat, msgs...)
   }
   return flat, nested
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
      c, err := compact(val)
      if err != nil {
         return nil, fmt.Errorf("compacting item %q: %w", key, err)
      }
      items = append(items, orderedItem{Key: key, Val: c})
   }
   if _, err := dec.Token(); err != nil { // closing '}'
      return nil, fmt.Errorf("parsing items object: %w", err)
   }
   return items, nil
}

// unit is one prunable message. Every message after unnesting gets one unit,
// wherever it came from: a later item, or a message found inside the first one.
type unit struct {
   key    string // item key, or "<item>:inner[n]" for a message found inside the first
   label  string // e.g. "message/user", "output_text"
   parts  []textPart
   size   int
   locked bool // the original first prompt: never removed
}

// buildUnits does step 1. The first message's text is either the original
// prompt or the output of a previous run; any part of it that is such output is
// expanded into the messages it holds, in order. The first message of the
// resulting list is the original prompt and is the only locked unit; every other
// message - unnested or not - is a removal candidate. Later items are one unit
// each, sized by their compacted JSON.
func buildUnits(items []orderedItem) ([]unit, error) {
   units := make([]unit, 0, len(items)+8)

   first := items[0]
   ps, err := textParts(first.Val)
   if err != nil {
      return nil, fmt.Errorf("extracting text from item %q: %w", first.Key, err)
   }
   flat, nested := unnestFirst(ps)

   fmt.Printf("First message %s [%s], %s\n", first.Key, itemLabel(first.Val), humanSize(len(first.Val)))

   if len(flat) == 0 {
      fmt.Printf("  no text in the first message; nothing kept from it\n")
   } else {
      if nested {
         fmt.Printf("  it holds the output of a previous run: %d message(s) inside\n", len(flat))
      }
      head, rest := flat[0], flat[1:]
      fmt.Printf("  original prompt (always kept): %q\n", preview(head.Text, 70))
      units = append(units, unit{
         key:    first.Key,
         label:  partLabel(head),
         parts:  []textPart{head},
         size:   partSize(head),
         locked: true,
      })
      if len(rest) > 0 {
         fmt.Printf("  %d other message(s) inside it, each prunable on its own\n", len(rest))
      }
      for n, p := range rest {
         units = append(units, innerUnit(first.Key, p, n+1))
      }
   }

   for _, it := range items[1:] {
      ps, err := textParts(it.Val)
      if err != nil {
         return nil, fmt.Errorf("extracting text from item %q: %w", it.Key, err)
      }
      units = append(units, unit{
         key:   it.Key,
         label: itemLabel(it.Val),
         parts: ps,
         size:  len(it.Val),
      })
   }
   return units, nil
}

// innerUnit wraps one message found inside the first message as its own unit.
func innerUnit(key string, p textPart, n int) unit {
   return unit{
      key:   fmt.Sprintf("%s:inner[%d]", key, n),
      label: partLabel(p),
      parts: []textPart{p},
      size:  partSize(p),
   }
}

// end main.go
