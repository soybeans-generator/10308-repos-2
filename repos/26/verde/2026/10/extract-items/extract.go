// extract.go — text extraction: walk decoded JSON, pull out the text, recognise this tool's own previous output.
package main

import (
   "bytes"
   "encoding/json"
   "fmt"
   "strconv"
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

// stripFences removes markdown code fences wrapped around s — e.g.
//
//   ```json
//   [ ... ]
//   ```
//
// Repeated fences are removed too, as are bare ones without a language tag. Only
// the very start and very end are touched; nothing between them is modified. A
// trailing fence is only removed if the string actually started with one, so
// content that merely ends in backticks is left alone.
func stripFences(s string) string {
   for i := 0; i < 8; i++ {
      t := strings.TrimSpace(s)
      fenced := false
      if strings.HasPrefix(t, "```") {
         fenced = true
         if nl := strings.IndexByte(t, '\n'); nl >= 0 {
            t = t[nl+1:] // drop the "```json" line
         } else {
            t = strings.TrimLeft(t[3:], "`")
         }
         t = strings.TrimSpace(t)
      }
      if fenced && strings.HasSuffix(t, "```") {
         t = strings.TrimSpace(t[:len(t)-3])
      }
      if t == strings.TrimSpace(s) {
         return t
      }
      s = t
   }
   return strings.TrimSpace(s)
}

// unquoteJSON unwraps a JSON string literal, for output that reached the message
// escaped rather than as raw JSON.
func unquoteJSON(s string) (string, bool) {
   if len(s) > 1 && s[0] == '"' && s[len(s)-1] == '"' {
      if u, err := strconv.Unquote(s); err == nil {
         return u, true
      }
   }
   return "", false
}

// kv is one object member buffered so document order survives.
type kv struct {
   key string
   val json.RawMessage
}

// textPart is one piece of text pulled out of an item, plus the "type" that
// accompanied it in the source (input_text, output_text, thinking, ...).
// Type is omitted when the source had none.
type textPart struct {
   Type string `json:"type,omitempty"`
   Text string `json:"text"`
}

// parseExportArray parses s as this tool's flat output, strictly: a non-empty
// array whose elements have only "text" and optional "type", with "text" a
// string.
func parseExportArray(s string) ([]textPart, bool) {
   var elems []json.RawMessage
   if err := json.Unmarshal([]byte(s), &elems); err != nil || len(elems) == 0 {
      return nil, false
   }
   parts := make([]textPart, 0, len(elems))
   for _, e := range elems {
      var obj map[string]json.RawMessage
      if err := json.Unmarshal(e, &obj); err != nil {
         return nil, false
      }
      for k := range obj {
         if k != "text" && k != "type" {
            return nil, false // some other array-of-objects: not our output
         }
      }
      var probe struct {
         Type string  `json:"type"`
         Text *string `json:"text"`
      }
      if err := json.Unmarshal(e, &probe); err != nil || probe.Text == nil {
         return nil, false
      }
      parts = append(parts, textPart{Type: probe.Type, Text: *probe.Text})
   }
   return parts, true
}

// splitExport reports whether s is output written by this tool — a JSON array
// whose elements carry only a string "text" and an optional string "type" — and
// if so returns its elements as text parts. The array may arrive bare, as a JSON
// string literal, or wrapped in markdown code fences, which is how such output
// usually ends up pasted back in. A false result means s is ordinary text, i.e.
// the original prompt.
func splitExport(s string) ([]textPart, bool) {
   t := strings.TrimSpace(s)
   if u, ok := unquoteJSON(t); ok {
      t = strings.TrimSpace(u)
   }
   t = stripFences(t)
   if len(t) < 2 || t[0] != '[' {
      return nil, false
   }
   if parts, ok := parseExportArray(t); ok {
      return parts, true
   }
   // Tolerate trailing prose after the closing bracket.
   if i := strings.LastIndexByte(t, ']'); i > 0 {
      return parseExportArray(t[:i+1])
   }
   return nil, false
}

// textParts returns every text block in an item, in document order.
func textParts(raw json.RawMessage) ([]textPart, error) {
   parts := make([]textPart, 0, 4)
   if err := collectFromValue(raw, "", &parts); err != nil {
      return nil, err
   }
   return parts, nil
}

// end extract.go
