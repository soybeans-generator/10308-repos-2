// probe.go marker preserve
package main

import (
   "bufio"
   "bytes"
   "encoding/json"
   "fmt"
   "io"
   "net/http"
   "strings"
   "time"
)

func errorNote(status int, raw []byte) string {
   var e struct {
      Error apiError `json:"error"`
   }
   if err := json.Unmarshal(raw, &e); err == nil {
      msg := strings.TrimSpace(e.Error.Message)
      if e.Error.Metadata != nil {
         if len(e.Error.Metadata.Reasons) > 0 {
            msg += " reasons=" + strings.Join(e.Error.Metadata.Reasons, ",")
         }
         if e.Error.Metadata.Raw != "" && strings.Contains(msg, "Provider returned error") {
            msg = strings.TrimSpace(e.Error.Metadata.Raw)
         }
      }
      if msg != "" {
         return truncate(fmt.Sprintf("HTTP %d: %s", status, msg), 160)
      }
   }
   return truncate(fmt.Sprintf("HTTP %d: %s", status, string(raw)), 160)
}

func httpStatus(status int, raw []byte) string {
   low := strings.ToLower(string(raw))
   switch {
   case status == 429:
      return "RATE"
   case status == 403:
      return "FILTERED"
   case strings.Contains(low, "moderation"), strings.Contains(low, "flagged"),
      strings.Contains(low, "content policy"), strings.Contains(low, "safety"):
      return "FILTERED"
   }
   return "ERROR"
}

func truncate(s string, n int) string {
   s = strings.Join(strings.Fields(s), " ")
   r := []rune(s)
   if len(r) <= n {
      return s
   }
   if n <= 3 {
      return string(r[:n])
   }
   return string(r[:n-3]) + "..."
}

type apiError struct {
   Message  string `json:"message"`
   Metadata *struct {
      Raw     string   `json:"raw"`
      Reasons []string `json:"reasons"`
   } `json:"metadata"`
}

// chatRequest has no max_tokens field. Output length is not constrained by this
// program: the field is simply absent, so the provider applies its own maximum
// for the model. Sending a value was the source of two failures that had nothing
// to do with the reply itself — an explicit 262,144 on a model whose served
// context is 262,144 total (prompt included) answered 400, and explicit values
// of 128,000 and 943,718 answered 402 because max_tokens is a credit
// reservation, not a spend. Omitting the field removes both, because there is no
// number left to reserve or to overrun the context with.
type chatRequest struct {
   Model       string     `json:"model"`
   Messages    []message  `json:"messages"`
   Temperature float64    `json:"temperature"`
   Stream      bool       `json:"stream"`
   Reasoning   *reasoning `json:"reasoning,omitempty"`
}

type chunk struct {
   Choices []chunkChoice `json:"choices"`
   Error   *apiError     `json:"error"`
}

type chunkChoice struct {
   Delta        delta  `json:"delta"`
   FinishReason string `json:"finish_reason"`
}

type delta struct {
   Content          string `json:"content"`
   Reasoning        string `json:"reasoning"`
   ReasoningContent string `json:"reasoning_content"`
}

type message struct {
   Role    string `json:"role"`
   Content string `json:"content"`
}

// reasoning carries enabled for models that can switch reasoning off, and
// effort for models that cannot. The zero value marshals to {}, so
// reasoningSpec returns nil rather than an empty struct when no field should be
// sent.
type reasoning struct {
   Enabled *bool  `json:"enabled,omitempty"`
   Effort  string `json:"effort,omitempty"`
}

// result is what one probe produced. It carries no model id: the caller already
// knows which model it asked, and it logs and records that id from modelInfo.
// Millis is the whole probe measured start to finish, which for a
// mandatory-reasoning model includes every token of thinking before the first
// character of the reply. It is reported in the progress line and nothing else.
type result struct {
   Status string
   Text   string
   Millis int64
}

// probe sends exactly one request carrying `prompt`, which is the task file text
// with outputDirective already appended, and returns whatever it produced.
//
// The reasoning object comes from the catalog metadata (modelInfo.reasoningSpec):
// lowest effort the model accepts, or off where the allowlist says "none" is
// available. That is the whole of the economising: the request carries no
// max_tokens, so the provider's own limit applies and a model that thinks for a
// long time is allowed to finish rather than being cut off. No outcome is
// followed by a second attempt.
//
// The request carries no deadline either, so the stream loop reads until the
// provider is done. The provider's own output limit and its own behaviour are
// the only things that end a reply; a connection that stalls instead of closing
// will block here. Millis is stamped on every return path, so a probe that
// failed still reports how long it took to fail.
func probe(client *http.Client, key string, m modelInfo, prompt string) result {
   var r result
   start := time.Now()

   body, err := json.Marshal(chatRequest{
      Model:       m.ID,
      Messages:    []message{{Role: "user", Content: prompt}},
      Temperature: 0,
      Stream:      true,
      Reasoning:   m.reasoningSpec(),
   })
   if err != nil {
      r.Status, r.Text = "ERROR", "marshal: "+err.Error()
      r.Millis = time.Since(start).Milliseconds()
      return r
   }

   hr, err := http.NewRequest(http.MethodPost, apiBase+"/chat/completions", bytes.NewReader(body))
   if err != nil {
      r.Status, r.Text = "ERROR", "request: "+err.Error()
      r.Millis = time.Since(start).Milliseconds()
      return r
   }
   hr.Header.Set("Authorization", "Bearer "+key)
   hr.Header.Set("Content-Type", "application/json")
   hr.Header.Set("Accept", "text/event-stream")

   resp, err := client.Do(hr)
   if err != nil {
      r.Millis = time.Since(start).Milliseconds()
      r.Status, r.Text = "ERROR", truncate("transport: "+err.Error(), 100)
      return r
   }
   defer resp.Body.Close()

   if resp.StatusCode < 200 || resp.StatusCode >= 300 {
      raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
      r.Millis = time.Since(start).Milliseconds()
      r.Text = errorNote(resp.StatusCode, raw)
      r.Status = httpStatus(resp.StatusCode, raw)
      return r
   }

   var content, reasoningText strings.Builder
   var finish string
   var streamErr *apiError

   sc := bufio.NewScanner(resp.Body)
   sc.Buffer(make([]byte, 0, 64<<10), 1<<20)

   // Read the stream to completion: no early break, so the reply is stored
   // whole. Nothing bounds the wait.
   for sc.Scan() {
      line := sc.Text()
      if !strings.HasPrefix(line, "data:") {
         continue
      }
      p := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
      if p == "" {
         continue
      }
      if p == "[DONE]" {
         break
      }

      var ch chunk
      if err := json.Unmarshal([]byte(p), &ch); err != nil {
         continue
      }
      if ch.Error != nil {
         streamErr = ch.Error
         break
      }

      for _, c := range ch.Choices {
         if c.Delta.Content != "" {
            content.WriteString(c.Delta.Content)
         }
         if c.Delta.Reasoning != "" {
            reasoningText.WriteString(c.Delta.Reasoning)
         }
         if c.Delta.ReasoningContent != "" {
            reasoningText.WriteString(c.Delta.ReasoningContent)
         }
         if c.FinishReason != "" {
            finish = c.FinishReason
         }
      }
   }

   r.Millis = time.Since(start).Milliseconds()

   if streamErr != nil {
      raw, _ := json.Marshal(map[string]any{"error": streamErr})
      r.Text = errorNote(200, raw)
      r.Status = "ERROR"
      low := strings.ToLower(r.Text)
      if strings.Contains(low, "moderation") || strings.Contains(low, "flagged") || strings.Contains(low, "safety") {
         r.Status = "FILTERED"
      }
      return r
   }

   text := strings.TrimSpace(content.String())
   think := strings.TrimSpace(reasoningText.String())

   if text == "" {
      switch {
      case strings.EqualFold(finish, "content_filter"):
         r.Status, r.Text = "FILTERED", "finish_reason=content_filter"
      case think != "":
         // The reply never appeared. finish_reason says why: "length" means the
         // provider's own output limit was reached while reasoning.
         r.Status = "ABSENT"
         r.Text = fmt.Sprintf("%d chars of reasoning, no content (finish_reason=%q)", len([]rune(think)), finish)
      default:
         // No content and no reasoning: the stream ended without a reply.
         r.Status = "ERROR"
         r.Text = fmt.Sprintf("stream ended with no content (finish_reason=%q)", finish)
      }
      return r
   }

   if strings.EqualFold(finish, "content_filter") {
      r.Status = "FILTERED"
   } else {
      r.Status = "TEXT"
   }
   r.Text = text
   return r
}

// probe.go marker preserve
