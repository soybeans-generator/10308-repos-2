// token.go
package criterion

import (
   "errors"
   "fmt"
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
   AccessToken string `json:"access_token"`
   // RefreshToken is returned because Scope asks for offline_access, but this
   // package has no refresh path: once AccessToken expires the user runs the
   // device flow again.
   RefreshToken string `json:"refresh_token"`
   IDToken      string `json:"id_token"`
   Scope        string `json:"scope"`
   ExpiresIn    int    `json:"expires_in"`
   TokenType    string `json:"token_type"`

   Error            string `json:"error,omitempty"`
   ErrorDescription string `json:"error_description,omitempty"`
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

// token.go
