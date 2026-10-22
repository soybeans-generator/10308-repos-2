// login_test.go
package criterion

import (
   "context"
   "encoding/json"
   "errors"
   "os"
   "path/filepath"
   "testing"
   "time"
)

// statePath is where TestLoginBeforeCode parks what TestLoginAfterCode needs.
// The device code is single-use and short-lived, but it is still a credential,
// so the file is written 0600, should be gitignored, and is deleted once the
// exchange succeeds.
const statePath = "testdata/login-state.json"

// live skips the test unless it was explicitly asked for, so a plain
// `go test ./...` never hits the network or blocks on a human.
func live(t *testing.T) {
   t.Helper()
   if os.Getenv("CRITERION_LOGIN_TEST") == "" {
      t.Skip("live login: set CRITERION_LOGIN_TEST=1 to run")
   }
}

// TestLoginBeforeCode runs up to the point where the user has to act: it
// fetches the anonymous init token, requests a device code, and writes the
// device code to statePath.
func TestLoginBeforeCode(t *testing.T) {
   live(t)
   ctx := context.Background()
   client := NewClient()

   init, err := Init(ctx, client)
   if err != nil {
      t.Fatalf("init: %v", err)
   }

   code, err := RequestDeviceCode(ctx, client)
   if err != nil {
      t.Fatalf("device code: %v", err)
   }

   state := loginState{
      InitToken:               init.Token,
      APIBaseURL:              init.BaseURL[init.Country],
      DeviceCode:              code.DeviceCode,
      UserCode:                code.UserCode,
      VerificationURI:         code.VerificationURI,
      VerificationURIComplete: code.VerificationURIComplete,
      ExpiresIn:               code.ExpiresIn,
      RequestedAt:             time.Now().UTC(),
   }

   blob, err := json.MarshalIndent(state, "", "  ")
   if err != nil {
      t.Fatalf("encode state: %v", err)
   }
   if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
      t.Fatalf("create %s: %v", filepath.Dir(statePath), err)
   }
   if err := os.WriteFile(statePath, blob, 0o600); err != nil {
      t.Fatalf("write %s: %v", statePath, err)
   }

   t.Logf("wrote %s", statePath)
   t.Logf("open %s", state.VerificationURIComplete)
   t.Logf("or go to %s and enter %s", state.VerificationURI, state.UserCode)
   t.Logf("code valid until %s", state.expiresAt().Format(time.RFC3339))
   t.Log("then run: CRITERION_LOGIN_TEST=1 go test -run TestLoginAfterCode -v")
}

// TestLoginAfterCode makes the single token request, assuming the user has
// meanwhile entered the code from TestLoginBeforeCode.
func TestLoginAfterCode(t *testing.T) {
   live(t)

   blob, err := os.ReadFile(statePath)
   if err != nil {
      t.Fatalf("read %s: %v (run TestLoginBeforeCode first)", statePath, err)
   }
   var state loginState
   if err := json.Unmarshal(blob, &state); err != nil {
      t.Fatalf("decode %s: %v", statePath, err)
   }

   if now := time.Now().UTC(); now.After(state.expiresAt()) {
      t.Fatalf("device code %s expired at %s; re-run TestLoginBeforeCode",
         state.UserCode, state.expiresAt().Format(time.RFC3339))
   }

   tokens, err := RequestToken(context.Background(), NewClient(), state.DeviceCode)
   switch {
   case errors.Is(err, ErrAuthorizationPending):
      t.Skipf("code %s not approved yet: open %s, then re-run this test",
         state.UserCode, state.VerificationURI)
   case errors.Is(err, ErrAccessDenied):
      t.Fatalf("authorization denied for code %s", state.UserCode)
   case errors.Is(err, ErrExpiredToken):
      t.Fatalf("device code %s expired; re-run TestLoginBeforeCode", state.UserCode)
   case errors.Is(err, ErrSlowDown):
      t.Fatalf("server asked to slow down; wait a few seconds and re-run this test")
   case err != nil:
      t.Fatalf("token: %v", err)
   }

   t.Logf("login OK, access token expires %s", tokens.Expiry().Format(time.RFC3339))
   t.Logf("scope=%q token_type=%q", tokens.Scope, tokens.TokenType)
   t.Logf("access_token:  %s", tokens.AccessToken)
   t.Logf("refresh_token: %s", tokens.RefreshToken)
   t.Logf("id_token:      %s", tokens.IDToken)

   // The device code is single use, so the hand-off file is dead weight now
   // and it contains credentials.
   if err := os.Remove(statePath); err != nil {
      t.Logf("could not remove %s: %v", statePath, err)
   } else {
      t.Logf("removed %s", statePath)
   }
}

// loginState is the hand-off between the two tests. No cookies: the device
// grant is keyed on DeviceCode alone (see the HAR — both POSTs carry an empty
// cookie list).
type loginState struct {
   InitToken               string    `json:"init_token"`
   APIBaseURL              string    `json:"api_base_url"`
   DeviceCode              string    `json:"device_code"`
   UserCode                string    `json:"user_code"`
   VerificationURI         string    `json:"verification_uri"`
   VerificationURIComplete string    `json:"verification_uri_complete"`
   ExpiresIn               int       `json:"expires_in"`
   RequestedAt             time.Time `json:"requested_at"`
}

// expiresAt is when the device code stops being usable.
func (s *loginState) expiresAt() time.Time {
   return s.RequestedAt.Add(time.Duration(s.ExpiresIn) * time.Second)
}

// login_test.go
