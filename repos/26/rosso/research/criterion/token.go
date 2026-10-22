// token.go
package criterion

import (
   "context"
   "encoding/json"
   "errors"
   "fmt"
   "io"
   "net/http"
   "net/url"
   "strings"
   "time"
)

// Sentinel errors for the OAuth error codes of the device grant. Anything else
// comes back as a plain error, so callers can match with errors.Is.
var (
   ErrAuthorizationPending = errors.New("criterion: authorization pending")
   ErrSlowDown             = errors.New("criterion: slow down")
   ErrAccessDenied         = errors.New("criterion: authorization denied by user")
   ErrExpiredToken         = errors.New("criterion: device code expired")
)

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

// TokenSet is the body of POST /oauth/token. On a non-200 answer the OAuth
// error fields are filled instead of the tokens.
type TokenSet struct {
   AccessToken  string `json:"access_token"`
   RefreshToken string `json:"refresh_token"`
   IDToken      string `json:"id_token"`
   Scope        string `json:"scope"`
   ExpiresIn    int    `json:"expires_in"`
   TokenType    string `json:"token_type"`

   Error            string `json:"error,omitempty"`
   ErrorDescription string `json:"error_description,omitempty"`
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
// nil TokenSet and an error wrapping one of the sentinels above, so a caller
// that wants to retry can distinguish ErrAuthorizationPending from a real
// failure without parsing strings.
func RequestToken(ctx context.Context, client *http.Client, deviceCode string) (*TokenSet, error) {
   form := url.Values{
      "client_id":   {ClientID},
      "device_code": {deviceCode},
      "grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
   }

   req, err := http.NewRequestWithContext(ctx, http.MethodPost,
      LoginBaseURL+"/oauth/token", strings.NewReader(form.Encode()))
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

// Expiry is when AccessToken stops being valid.
func (t *TokenSet) Expiry() time.Time {
   return time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
}

// token.go
