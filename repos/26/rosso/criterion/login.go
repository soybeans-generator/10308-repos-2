// login.go marker preserve
package criterion

import (
   "encoding/json"
   "errors"
   "fmt"
   "io"
   "log"
   "net/http"
   "net/url"
   "strings"
   "time"
)

// token.go marker preserve
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

// Sentinel errors for the OAuth error codes of the device grant. Anything else
// comes back as a plain error, so callers can match with errors.Is.
var (
   ErrAuthorizationPending = errors.New("criterion: authorization pending")
   ErrSlowDown             = errors.New("criterion: slow down")
   ErrAccessDenied         = errors.New("criterion: authorization denied by user")
   ErrExpiredToken         = errors.New("criterion: device code expired")
)

// do sends req on http.DefaultClient, logging method and URL. Every call in the
// package goes through here: the catalogue (VHX) calls and the login calls
// alike.
func do(req *http.Request) (*http.Response, error) {
   log.Println(req.Method, req.URL)
   return http.DefaultClient.Do(req)
}

// oauthError maps an OAuth error code to a wrapped sentinel.
func oauthError(t *TokenSet) error {
   var base error
   switch t.Error {
   case "authorization_pending":
      base = ErrAuthorizationPending
   case "slow_down":
      base = ErrSlowDown
   case "access_denied":
      base = ErrAccessDenied
   case "expired_token":
      base = ErrExpiredToken
   default:
      return fmt.Errorf("token: %s: %s", t.Error, t.ErrorDescription)
   }
   if t.ErrorDescription == "" {
      return base
   }
   return fmt.Errorf("%w: %s", base, t.ErrorDescription)
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

// TokenSet is the body of POST /oauth/token. On a non-200 answer the OAuth
// error fields are filled instead of the tokens.
type TokenSet struct {
   AccessToken string `json:"access_token"`
   // RefreshToken is returned because Scope asks for offline_access. Feed it to
   // RequestRefresh to get a new AccessToken without another device flow.
   RefreshToken string `json:"refresh_token"`
   IDToken      string `json:"id_token"`
   Scope        string `json:"scope"`
   ExpiresIn    int    `json:"expires_in"`
   TokenType    string `json:"token_type"`

   Error            string `json:"error,omitempty"`
   ErrorDescription string `json:"error_description,omitempty"`
}

// RequestRefresh performs a single POST https://login.criterion.com/oauth/token
// with body:
//
//   client_id=trliIpKF50NOVoCOBBPWO0Z51xjg1VBd
//   refresh_token=<refresh_token>
//   grant_type=refresh_token
//
// This is the cheap half of the device flow: no new device code, no user
// interaction, just a fresh AccessToken (and normally a fresh IDToken).
//
// Auth0 may rotate the refresh token. When the answer carries no refresh_token
// the old one remains valid, so a caller that keeps only the returned TokenSet
// should copy the previous RefreshToken onto it before caching. If the token has
// expired, been revoked, or was already used, Auth0 answers invalid_grant and
// this returns a plain error (no sentinel): the user has to run the device flow
// again.
func RequestRefresh(refreshToken string) (*TokenSet, error) {
   if refreshToken == "" {
      return nil, errors.New("refresh: empty refresh token")
   }
   return postToken(url.Values{
      "client_id":     {ClientID},
      "refresh_token": {refreshToken},
      "grant_type":    {"refresh_token"},
   })
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
   return postToken(url.Values{
      "client_id":   {ClientID},
      "device_code": {deviceCode},
      "grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
   })
}

// postToken posts an already-built /oauth/token form and decodes the answer.
// Every grant goes through it: the wire format and the error mapping are the
// same, only the form differs.
func postToken(form url.Values) (*TokenSet, error) {
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

// CachePath reports where the token set is cached. Unchanged from the
// password-grant implementation so existing caches still resolve.
func (*TokenSet) CachePath() string {
   return "rosso/criterion/Token"
}

// Expiry is when AccessToken stops being valid, measured from the moment this
// is called.
func (t *TokenSet) Expiry() time.Time {
   return time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
}

// login.go marker preserve
