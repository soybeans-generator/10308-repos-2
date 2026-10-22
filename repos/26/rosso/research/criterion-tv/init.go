// init.go
package criterion

import (
   "context"
   "encoding/json"
   "fmt"
   "io"
   "net/http"
   "net/http/cookiejar"
   "time"
)

const (
   // APIBaseURL is the mobile API host (no trailing slash).
   APIBaseURL = "https://mw.criterion.com/api"
   // LoginBaseURL is the Auth0 tenant that runs the device flow.
   LoginBaseURL = "https://login.criterion.com"
   // ClientID is the app's public OAuth client id.
   ClientID = "trliIpKF50NOVoCOBBPWO0Z51xjg1VBd"
   // Scope requested by the app.
   Scope = "openid profile email offline_access"
   // UserAgent mimics the Android client.
   UserAgent = "okhttp/5.3.2"
)

// NewClient returns a client with a cookie jar. The device flow sets a `did`
// cookie on the /oauth/device/code response and the /oauth/token poll is
// expected to send it back, so a plain http.Client will not work.
func NewClient() *http.Client {
   jar, err := cookiejar.New(nil)
   if err != nil {
      panic(err)
   }
   return &http.Client{Jar: jar, Timeout: 30 * time.Second}
}

// InitResponse is the body of GET /api/init.
type InitResponse struct {
   Country         string            `json:"country"`
   Token           string            `json:"token"`
   SunsetThreshold int               `json:"sunsetThreshold"`
   BaseURL         map[string]string `json:"baseUrl"`
   MinVersion      map[string]string `json:"min_version"`
}

// Init performs GET https://mw.criterion.com/api/init.
// No authorization is needed; the returned JWT is the anonymous token sent as
// `Authorization: Bearer <token>` on every subsequent API call, and
// BaseURL[country] selects the country-scoped API prefix (/api/us, /api/ca...).
func Init(ctx context.Context, client *http.Client) (*InitResponse, error) {
   req, err := http.NewRequestWithContext(ctx, http.MethodGet, APIBaseURL+"/init", nil)
   if err != nil {
      return nil, err
   }
   req.Header.Set("User-Agent", UserAgent)

   resp, err := client.Do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   if resp.StatusCode != http.StatusOK {
      body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
      return nil, fmt.Errorf("init: unexpected status %d: %s", resp.StatusCode, body)
   }

   var out InitResponse
   if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
      return nil, fmt.Errorf("init: decode: %w", err)
   }
   return &out, nil
}

// init.go
