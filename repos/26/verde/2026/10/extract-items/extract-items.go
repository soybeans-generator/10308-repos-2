package main

import (
   "bytes"
   "encoding/json"
   "flag"
   "fmt"
   "os"
   "sort"
   "strings"
)

// textKeys are the keys whose bare string values count as text. Objects are
// handled structurally instead: any object with a string "text" field is a
// part, no matter what it is nested under.
var textKeys = map[string]bool{
   "text":              true,
   "content":           true,
   "thinking":          true,
   "reasoning":         true,
   "reasoning_content": true,
   "output":            true,
   "message":           true,
   "summary":           true,
   "prompt":            true,
   "completion":        true,
   "value":             true,
   "body":              true,
   "delta":             true,
}

// collectFromObject reads an object whose '{' has already been consumed,
// buffering its members so document order survives. If the object carries a
// string "text" field, that is its text and its children are not descended
// into; otherwise every member is walked in order.
func collectFromObject(dec *json.Decoder, out *[]textPart) error {
   pairs := make([]kv, 0, 8)
   for dec.More() {
      kt, err := dec.Token()
      if err != nil {
         return err
      }
      key, ok := kt.(string)
      if !ok {
         return fmt.Errorf("unexpected object key token %v", kt)
      }
      var raw json.RawMessage
      if err := dec.Decode(&raw); err != nil {
         return err
      }
      pairs = append(pairs, kv{key: key, val: raw})
   }
   if _, err := dec.Token(); err != nil { // closing '}'
      return err
   }

   for _, p := range pairs {
      if !strings.EqualFold(p.key, "text") {
         continue
      }
      var s string
      if err := json.Unmarshal(p.val, &s); err != nil || strings.TrimSpace(s) == "" {
         continue
      }
      part := textPart{Text: s}
      for _, q := range pairs {
         if strings.EqualFold(q.key, "type") {
            var ts string
            if json.Unmarshal(q.val, &ts) == nil {
               part.Type = ts
            }
         }
      }
      *out = append(*out, part)
      return nil
   }

   for _, p := range pairs {
      if err := collectFromValue(p.val, p.key, out); err != nil {
         return err
      }
   }
   return nil
}

// collectFromValue walks one JSON value. key is the object key it sits under
// (or the key of the enclosing array), so bare strings under a text key are
// picked up even without a wrapping object.
func collectFromValue(raw json.RawMessage, key string, out *[]textPart) error {
   if len(bytes.TrimSpace(raw)) == 0 {
      return nil
   }
   dec := json.NewDecoder(bytes.NewReader(raw))
   tok, err := dec.Token()
   if err != nil {
      return err
   }

   switch t := tok.(type) {
   case string:
      if isTextField(key) && strings.TrimSpace(t) != "" {
         *out = append(*out, textPart{Text: t})
      }
   case json.Delim:
      switch t {
      case '{':
         return collectFromObject(dec, out)
      case '[':
         for dec.More() {
            var elem json.RawMessage
            if err := dec.Decode(&elem); err != nil {
               return err
            }
            if err := collectFromValue(elem, key, out); err != nil {
               return err
            }
         }
         _, err := dec.Token() // closing ']'
         return err
      default:
         return fmt.Errorf("unexpected delimiter %v", t)
      }
   }
   return nil
}

// compact removes insignificant whitespace from raw JSON, preserving key order.
func compact(raw json.RawMessage) (json.RawMessage, error) {
   var buf bytes.Buffer
   if err := json.Compact(&buf, raw); err != nil {
      return nil, err
   }
   return buf.Bytes(), nil
}

func humanSize(n int) string {
   const KB = 1024
   const MB = KB * 1024
   switch {
   case n >= MB:
      return fmt.Sprintf("%.2f MB (%d bytes)", float64(n)/float64(MB), n)
   case n >= KB:
      return fmt.Sprintf("%.2f KB (%d bytes)", float64(n)/float64(KB), n)
   default:
      return fmt.Sprintf("%d bytes", n)
   }
}

func isTextField(key string) bool {
   return textKeys[strings.ToLower(strings.TrimSpace(key))]
}

// itemLabel describes an item for reporting, e.g. "message/user".
func itemLabel(raw json.RawMessage) string {
   var probe struct {
      Data *struct {
         Type string `json:"type"`
         Role string `json:"role"`
      } `json:"data"`
   }
   if err := json.Unmarshal(raw, &probe); err != nil || probe.Data == nil {
      return "?"
   }
   t := probe.Data.Type
   if t == "" {
      t = "?"
   }
   if probe.Data.Role != "" {
      return t + "/" + probe.Data.Role
   }
   return t
}

func main() {
   inPath := flag.String("i", "", "input JSON file path")
   outPath := flag.String("o", "", "output JSON file path (compacted array of {type,text} objects)")
   removeCount := flag.Int("r", 0, "number of largest items to remove (by compacted size)")
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

   // Stream-decode the items object so keys are captured in original order.
   dec := json.NewDecoder(bytes.NewReader(itemsRaw))

   tok, err := dec.Token()
   if err != nil {
      return fmt.Errorf("parsing items object: %w", err)
   }
   if d, ok := tok.(json.Delim); !ok || d != '{' {
      return fmt.Errorf(`"items" is not a JSON object`)
   }

   items := make([]orderedItem, 0)
   for dec.More() {
      keyTok, err := dec.Token()
      if err != nil {
         return fmt.Errorf("parsing items object: %w", err)
      }
      key, ok := keyTok.(string)
      if !ok {
         return fmt.Errorf("unexpected token in items object: expected key string, got %v", keyTok)
      }

      var val json.RawMessage
      if err := dec.Decode(&val); err != nil {
         return fmt.Errorf("parsing item %q: %w", key, err)
      }
      c, err := compact(val)
      if err != nil {
         return fmt.Errorf("compacting item %q: %w", key, err)
      }
      items = append(items, orderedItem{Key: key, Val: c})
   }
   if _, err := dec.Token(); err != nil { // closing '}'
      return fmt.Errorf("parsing items object: %w", err)
   }

   origCompact, err := compact(itemsRaw)
   if err != nil {
      return fmt.Errorf("compacting items object: %w", err)
   }
   fmt.Printf("Original \"items\" object: %d items, size %s\n", len(items), humanSize(len(origCompact)))

   // If removeCount > 0, drop the N largest items (order of the rest is preserved).
   if removeCount > 0 {
      if removeCount > len(items) {
         return fmt.Errorf("-r %d exceeds number of items (%d)", removeCount, len(items))
      }

      idx := make([]int, len(items))
      for i := range idx {
         idx[i] = i
      }
      sort.SliceStable(idx, func(a, b int) bool {
         return len(items[idx[a]].Val) > len(items[idx[b]].Val)
      })

      remove := make(map[int]bool, removeCount)
      fmt.Printf("Removing %d largest item(s):\n", removeCount)
      for _, i := range idx[:removeCount] {
         fmt.Printf("  - %s [%s] : %s\n", items[i].Key, itemLabel(items[i].Val), humanSize(len(items[i].Val)))
         remove[i] = true
      }

      kept := make([]orderedItem, 0, len(items)-removeCount)
      for i, it := range items {
         if !remove[i] {
            kept = append(kept, it)
         }
      }
      items = kept
   }

   // One {type,text} object per text block found in each item, in order.
   // Items with no text contribute nothing.
   out := make([]textPart, 0, len(items))
   for _, it := range items {
      parts, err := textParts(it.Val)
      if err != nil {
         return fmt.Errorf("extracting text from item %q: %w", it.Key, err)
      }
      out = append(out, parts...)
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

   fmt.Printf("Final output: %d text block(s) from %d kept item(s), size %s\n",
      len(out), len(items), humanSize(len(finalBytes)))
   fmt.Printf("Wrote %s\n", outPath)
   return nil
}

type kv struct {
   key string
   val json.RawMessage
}

type orderedItem struct {
   Key string
   Val json.RawMessage
}

// textPart is one piece of text pulled out of an item, plus the "type" that
// accompanied it in the source (input_text, output_text, thinking, ...).
// Type is omitted when the source had none.
type textPart struct {
   Type string `json:"type,omitempty"`
   Text string `json:"text"`
}

// textParts returns every text block in an item, in document order.
func textParts(raw json.RawMessage) ([]textPart, error) {
   parts := make([]textPart, 0, 4)
   if err := collectFromValue(raw, "", &parts); err != nil {
      return nil, err
   }
   return parts, nil
}
