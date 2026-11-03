// main.go — extract-text: read an OpenRouter export, unnest the first message, drop reasoning parts, write flat output.
package main

import (
   "bytes"
   "encoding/json"
   "flag"
   "fmt"
   "os"
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

func main() {
   inPath := flag.String("i", "", "input JSON file path (an OpenRouter export)")
   outPath := flag.String("o", "", "output JSON file path (compacted array of {type,text} objects)")
   flag.Parse()

   if *inPath == "" || *outPath == "" {
      fmt.Fprintln(os.Stderr, "usage: extract-text -i <input.json> -o <output.json>")
      flag.PrintDefaults()
      os.Exit(1)
   }

   if err := run(*inPath, *outPath); err != nil {
      fmt.Fprintf(os.Stderr, "error: %v\n", err)
      os.Exit(1)
   }
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

func run(inPath, outPath string) error {
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

   // The first message is either the original prompt or a previous run's
   // output; expand the latter into the messages it holds. Its first part is
   // the original prompt and is never stripped.
   firstPs, err := textParts(items[0].Val)
   if err != nil {
      return fmt.Errorf("extracting text from item %q: %w", items[0].Key, err)
   }
   flat, nested := unnestFirst(firstPs)

   out := make([]textPart, 0, len(items)+len(flat))
   removedParts, removedBytes := 0, 0

   // drop records and reports one reasoning part. True means dropped.
   drop := func(p textPart) bool {
      if !isReasoningPart(p) {
         return false
      }
      removedParts++
      removedBytes += partSize(p)
      return true
   }

   fmt.Printf("First message %s [%s]: %d text part(s)%s\n",
      items[0].Key, itemLabel(items[0].Val), len(flat),
      map[bool]string{true: ", holds a previous run's output", false: ""}[nested])

   if len(flat) > 0 {
      prompt := flat[0]
      out = append(out, prompt) // locked: never stripped
      fmt.Printf("  original prompt: %q\n", preview(prompt.Text, 70))
      if isReasoningPart(prompt) {
         fmt.Printf("  note: prompt is typed %q; kept anyway\n", prompt.Type)
      }
      for _, p := range flat[1:] {
         if drop(p) {
            continue
         }
         out = append(out, p)
      }
   } else {
      fmt.Printf("  no text in the first message\n")
   }

   for _, it := range items[1:] {
      ps, err := textParts(it.Val)
      if err != nil {
         return fmt.Errorf("extracting text from item %q: %w", it.Key, err)
      }
      for _, p := range ps {
         if drop(p) {
            continue
         }
         out = append(out, p)
      }
   }

   if removedParts == 0 {
      fmt.Println("Reasoning parts: none found")
   } else {
      fmt.Printf("Removed %s reasoning part(s), %s\n",
         commas(removedParts), humanSize(removedBytes))
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
   fmt.Printf("Output: %d text object(s), %s, ~%s tokens (est.)\n",
      len(out), humanSize(len(finalBytes)), commas(tokens))
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
      items = append(items, orderedItem{Key: key, Val: val})
   }
   if _, err := dec.Token(); err != nil { // closing '}'
      return nil, fmt.Errorf("parsing items object: %w", err)
   }
   return items, nil
}

// end main.go
