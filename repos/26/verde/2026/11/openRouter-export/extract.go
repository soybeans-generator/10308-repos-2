// extract.go — extract-text: read an OpenRouter orpg.3 export, order messages by
// createdAt, unnest the oldest, drop reasoning parts, remove the oldest
// remaining messages, write a flat array of {type,text} objects.
//
// Rules, in order: order by message createdAt; unpack the oldest message if it
// holds a previous run's output; shield the oldest and the newest; drop reasoning
// from every message; remove the N oldest unprotected messages.
package main

import (
   "bytes"
   "encoding/json"
   "flag"
   "fmt"
   "os"
   "slices"
   "strings"
   "time"
)

// compact drops reasoning parts, removes the oldest unprotected messages, and
// writes the flat result. Messages arrive chronological and shielded.
func compact(msgs []msg, outPath string, removeN int) error {
   // The part is the unit, so a message mixing reasoning and content keeps the
   // content and goes only once empty.
   rParts := 0
   kept := msgs[:0]
   for _, m := range msgs {
      out := m.parts[:0]
      for _, p := range m.parts {
         if !isReasoningPart(p) {
            out = append(out, p)
         }
      }
      rParts += len(m.parts) - len(out)
      m.parts = out
      if len(m.parts) == 0 && !m.protected {
         continue
      }
      kept = append(kept, m)
   }
   fmt.Printf("Reasoning parts removed: %d\n", rParts)

   // kept is chronological, so one pass front to back removes the oldest.
   if removeN > 0 {
      removable := 0
      for _, m := range kept {
         if !m.protected {
            removable++
         }
      }
      if removeN > removable {
         return fmt.Errorf("-r %d exceeds the %d removable message(s); the oldest and the newest message are always kept",
            removeN, removable)
      }
      fmt.Printf("Removing %d oldest message(s):\n", removeN)
      live := make([]msg, 0, len(kept)-removeN)
      for _, m := range kept {
         if !m.protected && removeN > 0 {
            removeN--
            fmt.Printf("  - %s [%s]\n", m.key, m.label)
            continue
         }
         live = append(live, m)
      }
      kept = live
   }
   fmt.Printf("Kept %d message(s)\n", len(kept))
   fmt.Printf("  shielded: %s ... %s\n", kept[0].key, kept[len(kept)-1].key)

   out := make([]textPart, 0, len(kept))
   for _, m := range kept {
      out = append(out, m.parts...)
   }

   var buf bytes.Buffer
   enc := json.NewEncoder(&buf)
   enc.SetEscapeHTML(false)
   if err := enc.Encode(out); err != nil {
      return fmt.Errorf("marshaling final output: %w", err)
   }
   finalBytes := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
   if err := os.WriteFile(outPath, finalBytes, 0o644); err != nil {
      return fmt.Errorf("writing output: %w", err)
   }
   fmt.Printf("Output: %d text object(s) from %d message(s), %d bytes\n",
      len(out), len(kept), len(finalBytes))
   fmt.Printf("Wrote %s\n", outPath)
   return nil
}

// isReasoningPart reports whether a part's type marks it as chain-of-thought:
// reasoning_text, reasoning, reasoning.summary, thinking, ... Matching is by
// substring, and never fires on an absent type or on plain "text"/"input_text"/
// "output_text".
func isReasoningPart(p textPart) bool {
   t := strings.ToLower(p.Type)
   return t != "" && (strings.Contains(t, "reason") || strings.Contains(t, "think"))
}

func main() {
   inPath := flag.String("i", "", "input JSON file path (an OpenRouter export)")
   outPath := flag.String("o", "", "output JSON file path (compacted array of {type,text} objects)")
   removeN := flag.Int("r", 0,
      "number of oldest messages to remove, ordered by message createdAt, after unnesting and after reasoning is dropped; the oldest and the newest message are always kept")
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

   msgs, err := readMsgs(*inPath)
   if err != nil {
      fmt.Fprintf(os.Stderr, "error: %v\n", err)
      os.Exit(1)
   }
   msgs, err = shieldAndUnnest(msgs)
   if err != nil {
      fmt.Fprintf(os.Stderr, "error: %v\n", err)
      os.Exit(1)
   }
   if err := compact(msgs, *outPath, *removeN); err != nil {
      fmt.Fprintf(os.Stderr, "error: %v\n", err)
      os.Exit(1)
   }
}

// export is the top-level document. Only the two maps that carry the chat are
// read; the rest of the export is metadata this tool has no business reading.
type export struct {
   Messages map[string]message `json:"messages"`
   Items    map[string]item    `json:"items"`
}

// item is one piece of a message: a message body or a reasoning block.
type item struct {
   Data itemData `json:"data"`
}

// itemData holds an item's content parts. Status, role and id are not needed:
// the message carries the role and the timestamp, and the part carries its type.
// Content stays raw because the export writes it in more than one shape: an array
// of parts for ordinary messages, a bare string for some items, and no content at
// all for others (the st_* ones).
type itemData struct {
   Content json.RawMessage `json:"content"`
}

// itemRef points at an item by id. The array order is the order the parts belong
// in, so nothing else on the reference is read.
type itemRef struct {
   ID string `json:"id"`
}

// message is one turn. It holds no text itself: its items do. createdAt is what
// "oldest" means, and type is "user" or "assistant".
type message struct {
   Type      string    `json:"type"`
   CreatedAt string    `json:"createdAt"`
   Items     []itemRef `json:"items"`
}

// msg is one message; the unit N is removed from.
type msg struct {
   key       string    // message key
   label     string    // message label
   at        time.Time // creation time
   parts     []textPart
   protected bool // oldest or newest: never removed
}

// readMsgs reads the export and returns one message per chat turn, ordered by
// createdAt. The message id breaks ties so a shared timestamp cannot reorder runs.
func readMsgs(inPath string) ([]msg, error) {
   raw, err := os.ReadFile(inPath)
   if err != nil {
      return nil, fmt.Errorf("reading input: %w", err)
   }

   var ex export
   if err := json.Unmarshal(raw, &ex); err != nil {
      return nil, fmt.Errorf("parsing JSON: %w", err)
   }
   if len(ex.Messages) == 0 {
      return nil, fmt.Errorf("input has no messages")
   }
   fmt.Printf("Input: %d message(s), %d item(s), %d bytes\n",
      len(ex.Messages), len(ex.Items), len(raw))

   msgs := make([]msg, 0, len(ex.Messages))
   for id, m := range ex.Messages {
      if m.Type == "" {
         return nil, fmt.Errorf("message %q declares no type", id)
      }
      if m.CreatedAt == "" {
         return nil, fmt.Errorf("message %q has no createdAt", id)
      }
      at, err := time.Parse(time.RFC3339Nano, m.CreatedAt)
      if err != nil {
         return nil, fmt.Errorf("message %q createdAt %q: %w", id, m.CreatedAt, err)
      }

      var parts []textPart
      for _, ref := range m.Items {
         it, ok := ex.Items[ref.ID]
         if !ok {
            return nil, fmt.Errorf("message %q references missing item %q", id, ref.ID)
         }
         // No content key at all: the item holds no text, so it contributes none.
         if len(it.Data.Content) == 0 {
            continue
         }
         var content []textPart
         errArray := json.Unmarshal(it.Data.Content, &content)
         if errArray != nil {
            // A bare string becomes one untyped part, taken exactly as it decodes.
            var s string
            if err := json.Unmarshal(it.Data.Content, &s); err != nil {
               return nil, fmt.Errorf("item %q content: %w", ref.ID, errArray)
            }
            content = []textPart{{Text: s}}
         }
         for _, p := range content {
            if p.Text != "" {
               parts = append(parts, p)
            }
         }
      }
      msgs = append(msgs, msg{key: id, label: m.Type, at: at, parts: parts})
   }

   slices.SortStableFunc(msgs, func(a, b msg) int {
      if c := a.at.Compare(b.at); c != 0 {
         return c
      }
      return strings.Compare(a.key, b.key)
   })
   return msgs, nil
}

// shieldAndUnnest expands the oldest message if it carries a previous run's
// output, drops textless messages, and shields the oldest and the newest. Textless
// messages go first, so an empty turn cannot steal the shield.
func shieldAndUnnest(msgs []msg) ([]msg, error) {
   first := msgs[0]
   flat, nested := unnestFirst(first.parts)
   if nested {
      fmt.Printf("Oldest message %s [%s]: previous run's output unpacked into %d object(s)\n",
         first.key, first.label, len(flat))
      expanded := make([]msg, 0, len(msgs)+len(flat)-1)
      for i, p := range flat {
         key := first.key
         if i > 0 {
            key = fmt.Sprintf("%s:inner[%d]", first.key, i)
         }
         if p.Type == "" {
            return nil, fmt.Errorf("message %s: inner part has no type", key)
         }
         expanded = append(expanded, msg{key: key, label: p.Type, at: first.at, parts: []textPart{p}})
      }
      msgs = append(expanded, msgs[1:]...)
   }

   nonEmpty := msgs[:0]
   for _, m := range msgs {
      if len(m.parts) > 0 {
         nonEmpty = append(nonEmpty, m)
      }
   }
   msgs = nonEmpty
   if len(msgs) == 0 {
      return nil, fmt.Errorf("no text found in any message")
   }
   msgs[0].protected, msgs[len(msgs)-1].protected = true, true
   return msgs, nil
}

// textPart is one piece of text pulled out of an item, plus the "type" that
// accompanied it in the source. Type is omitted when the source had none.
type textPart struct {
   Type string `json:"type,omitempty"`
   Text string `json:"text"`
}

// parseExportArray parses s as this tool's flat output: a non-empty array of text
// parts. Extra keys are ignored; a missing text field means it is not our output.
func parseExportArray(s string) ([]textPart, bool) {
   var elems []struct {
      Type string  `json:"type"`
      Text *string `json:"text"`
   }
   if err := json.Unmarshal([]byte(s), &elems); err != nil || len(elems) == 0 {
      return nil, false
   }
   parts := make([]textPart, 0, len(elems))
   for _, e := range elems {
      if e.Text == nil {
         return nil, false
      }
      parts = append(parts, textPart{Type: e.Type, Text: *e.Text})
   }
   return parts, true
}

// splitExport reports whether s is output written by this tool and, if so, returns
// its elements as text parts. The array may arrive bare, as a JSON string literal,
// or padded with prose or a markdown fence; only the bracketed region is parsed,
// taken from the string as given. Nothing is trimmed, collapsed, or rewritten.
// False means s is ordinary text, i.e. the original prompt.
func splitExport(s string) ([]textPart, bool) {
   if len(s) > 0 && s[0] == '"' {
      var u string
      if err := json.Unmarshal([]byte(s), &u); err != nil {
         // Quoted but not a JSON string literal: ordinary text, so
         // "not our output" is the answer, not a failure to report.
         return nil, false
      }
      s = u
   }
   start := strings.IndexByte(s, '[')
   end := strings.LastIndexByte(s, ']')
   if start < 0 || end <= start {
      return nil, false
   }
   return parseExportArray(s[start : end+1])
}

// unnestFirst expands every part of the oldest message that is a previous run's
// output into the messages it holds, in place, so index 0 stays the original
// prompt. The result is always flat, so one pass is enough.
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

// end extract.go
