// probe.go marker preserve
package main

import (
   "bufio"
   "bytes"
   "context"
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

type chatRequest struct {
   Model       string     `json:"model"`
   Messages    []message  `json:"messages"`
   Temperature float64    `json:"temperature"`
   MaxTokens   int        `json:"max_tokens"`
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
type result struct {
   Status string
   Text   string
   Millis int64
}

// probe sends exactly one request carrying `prompt`, which is the task file text
// with outputDirective already appended, and returns whatever it produced. The
// reasoning object comes from the catalog metadata (modelInfo.reasoningSpec):
// off where the model allows it, lowest effort where it does not. No outcome is
// followed by a second attempt.
func probe(client *http.Client, key string, m modelInfo, prompt string) result {
   var r result
   start := time.Now()

   body, err := json.Marshal(chatRequest{
      Model:       m.ID,
      Messages:    []message{{Role: "user", Content: prompt}},
      Temperature: 0,
      MaxTokens:   maxToks,
      Stream:      true,
      Reasoning:   m.reasoningSpec(),
   })
   if err != nil {
      r.Status, r.Text = "ERROR", "marshal: "+err.Error()
      r.Millis = time.Since(start).Milliseconds()
      return r
   }

   ctx, cancel := context.WithTimeout(context.Background(), timeout)
   defer cancel()

   hr, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/chat/completions", bytes.NewReader(body))
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
      if strings.Contains(err.Error(), "context deadline exceeded") ||
         strings.Contains(err.Error(), "Client.Timeout") {
         r.Status, r.Text = "TIMEOUT", fmt.Sprintf("no response within %s", timeout)
      } else {
         r.Status, r.Text = "ERROR", truncate("transport: "+err.Error(), 100)
      }
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
   // whole. maxToks bounds length; timeout bounds the wait.
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
         // The reply never appeared. finish_reason says why: "length" means
         // reasoning consumed max_tokens, empty means the stream was cut.
         r.Status = "ABSENT"
         r.Text = fmt.Sprintf("%d chars of reasoning, no content (finish_reason=%q)", len([]rune(think)), finish)
      default:
         r.Status = "TIMEOUT"
         r.Text = fmt.Sprintf("no content within %s", timeout)
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
