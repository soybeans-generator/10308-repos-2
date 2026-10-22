// devicecode.go
package criterion

import (
   "context"
   "encoding/json"
   "fmt"
   "io"
   "net/http"
   "net/url"
   "strings"
)

// DeviceCode is the body of POST /oauth/device/code.
type DeviceCode struct {
   DeviceCode              string `json:"device_code"`
   UserCode                string `json:"user_code"`
   VerificationURI         string `json:"verification_uri"`
   VerificationURIComplete string `json:"verification_uri_complete"`
   ExpiresIn               int    `json:"expires_in"`
}

// RequestDeviceCode performs POST https://login.criterion.com/oauth/device/code
// with body:
//
//   client_id=trliIpKF50NOVoCOBBPWO0Z51xjg1VBd
//   scope=openid profile email offline_access
//
// The user must open VerificationURIComplete (or VerificationURI and type
// UserCode) and approve the request. Once they have, call RequestToken once
// with DeviceCode. There is no polling: ExpiresIn is informational, so the
// caller can show the user how long the code remains valid.
//
// The response sets a `did` cookie that RequestToken must send back, so use
// the same http.Client (one with a cookie jar, see NewClient) for both calls.
func RequestDeviceCode(ctx context.Context, client *http.Client) (*DeviceCode, error) {
   form := url.Values{
      "client_id": {ClientID},
      "scope":     {Scope},
   }

   req, err := http.NewRequestWithContext(ctx, http.MethodPost,
      LoginBaseURL+"/oauth/device/code", strings.NewReader(form.Encode()))
   if err != nil {
      return nil, err
   }
   req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
   req.Header.Set("User-Agent", UserAgent)

   resp, err := client.Do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   if resp.StatusCode != http.StatusOK {
      body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
      return nil, fmt.Errorf("device/code: unexpected status %d: %s", resp.StatusCode, body)
   }

   var out DeviceCode
   if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
      return nil, fmt.Errorf("device/code: decode: %w", err)
   }
   return &out, nil
}

// devicecode.go
