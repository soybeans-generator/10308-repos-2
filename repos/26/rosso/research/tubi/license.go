package tubidrm

import (
   "bytes"
   "context"
   "fmt"
   "io"
   "net/http"
   "time"
)

// License posts body to v.URL and returns the response bytes unmodified.
//
// body is forwarded byte for byte; nothing is encoded, decoded or validated.
func License(ctx context.Context, hc *http.Client, v Values, body []byte) ([]byte, error) {
   if hc == nil {
      hc = &http.Client{Timeout: 30 * time.Second}
   }
   if v.URL == "" {
      return nil, fmt.Errorf("tubidrm: Values.URL is empty")
   }
   if len(body) == 0 {
      return nil, fmt.Errorf("tubidrm: empty request body")
   }

   req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.URL, bytes.NewReader(body))
   if err != nil {
      return nil, err
   }
   h := req.Header
   h.Set("Accept", "*/*")
   h.Set("Accept-Language", "en-US,en;q=0.5")
   h.Set("User-Agent", defaultUserAgent)
   h.Set("Origin", defaultOrigin)
   h.Set("Referer", defaultReferer)
   v.Apply(h)

   resp, err := hc.Do(req)
   if err != nil {
      return nil, fmt.Errorf("tubidrm: license request: %w", err)
   }
   defer resp.Body.Close()

   raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
   if err != nil {
      return nil, fmt.Errorf("tubidrm: reading license response: %w", err)
   }
   if resp.StatusCode != http.StatusOK {
      return nil, &StatusError{
         Op:     "license request",
         Status: resp.StatusCode,
         Body:   raw,
      }
   }
   return raw, nil
}

// StatusError is returned when a request fails with a non-200 status.
type StatusError struct {
   Op     string
   Status int
   Body   []byte
}

func (e *StatusError) Error() string {
   return fmt.Sprintf("tubidrm: %s: HTTP %d: %s", e.Op, e.Status, e.Body)
}
