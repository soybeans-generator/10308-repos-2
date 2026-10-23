// login.go
package criterion

import (
   "encoding/json"
   "fmt"
   "io"
   "log"
   "net/http"
   "net/url"
   "strings"
)

const (
   // LoginBaseURL is the Auth0 tenant that runs the device flow.
   LoginBaseURL = "https://login.criterion.com"
   // ClientID is the app's public OAuth client id.
   ClientID = "trliIpKF50NOVoCOBBPWO0Z51xjg1VBd"
   // Scope is what the app requests.
   Scope = "openid profile email offline_access"
   // UserAgent mimics the Android client.
   UserAgent = "okhttp/5.3.2"
)

// do sends req on http.DefaultClient, logging method and URL. Every call in the
// package goes through here: the catalogue (VHX) calls and the login calls
// alike.
//
// DefaultClient has no cookie jar, which matches okhttp (the real client): the
// HAR shows both /oauth/device/code and /oauth/token with an empty cookie list.
func do(req *http.Request) (*http.Response, error) {
   log.Println(req.Method, req.URL)
   return http.DefaultClient.Do(req)
}

// RequestToken performs a single POST https://login.criterion.com/oauth/token
// with body:
//
//   client_id=trliIpKF50NOVoCOBBPWO0Z51xjg1VBd
//   device_code=<device_code>
//   grant_type=urn:ietf:params:oauth:grant-type:device_code
//
// Call it once, after the user has entered the code at VerificationURI and
// approved it. There is no polling here.
//
// On approval it returns the TokenSet with a nil error. Otherwise it returns a
// nil TokenSet and an error wrapping one of the sentinels in token.go, so a
// caller that wants to retry can distinguish ErrAuthorizationPending from a
// real failure without parsing strings.
func RequestToken(deviceCode string) (*TokenSet, error) {
   form := url.Values{
      "client_id":   {ClientID},
      "device_code": {deviceCode},
      "grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
   }

   req, err := http.NewRequest(http.MethodPost,
      LoginBaseURL+"/oauth/token", strings.NewReader(form.Encode()))
   if err != nil {
      return nil, err
   }
   req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
   req.Header.Set("User-Agent", UserAgent)

   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   body, err := io.ReadAll(resp.Body)
   if err != nil {
      return nil, err
   }

   var out TokenSet
   if err := json.Unmarshal(body, &out); err != nil {
      return nil, fmt.Errorf("token: status %d, decode: %w", resp.StatusCode, err)
   }

   if out.Error != "" {
      return nil, oauthError(&out)
   }
   if resp.StatusCode != http.StatusOK {
      return nil, fmt.Errorf("token: unexpected status %d: %s", resp.StatusCode, body)
   }
   return &out, nil
}

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
// Nothing is carried between this call and RequestToken except the device code
// itself.
func RequestDeviceCode() (*DeviceCode, error) {
   form := url.Values{
      "client_id": {ClientID},
      "scope":     {Scope},
   }

   req, err := http.NewRequest(http.MethodPost,
      LoginBaseURL+"/oauth/device/code", strings.NewReader(form.Encode()))
   if err != nil {
      return nil, err
   }
   req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
   req.Header.Set("User-Agent", UserAgent)

   resp, err := do(req)
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

// CachePath reports where the pending device code is cached between the two
// login steps. Same idea as Token and File: one fixed path, no per-value keying.
func (*DeviceCode) CachePath() string {
   return "rosso/criterion/DeviceCode"
}

// login.go
