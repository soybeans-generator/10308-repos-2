// token.go
package criterion

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TokenSet is the body of POST /oauth/token. On failure the OAuth error fields
// are filled instead of the tokens.
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

// Expiry is when AccessToken stops being valid.
func (t *TokenSet) Expiry() time.Time {
	return time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
}

// RequestToken performs a single POST https://login.criterion.com/oauth/token
// with body:
//
//	client_id=trliIpKF50NOVoCOBBPWO0Z51xjg1VBd
//	device_code=<device_code>
//	grant_type=urn:ietf:params:oauth:grant-type:device_code
//
// While the user has not approved yet the server answers 400/403 with
// error=authorization_pending (or slow_down); that is returned here as a
// *TokenSet with Error set, not as a transport error.
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
	if resp.StatusCode != http.StatusOK && out.Error == "" {
		return nil, fmt.Errorf("token: unexpected status %d: %s", resp.StatusCode, body)
	}
	return &out, nil
}

// PollForToken repeats RequestToken every Interval seconds until the user
// approves the device (success), or the code expires / is denied.
// The resulting AccessToken is sent as `Authorization: Bearer <access_token>`
// to the mw.criterion.com API.
func PollForToken(ctx context.Context, client *http.Client, code *DeviceCode) (*TokenSet, error) {
	interval := time.Duration(code.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	deadline := code.Expiry()

	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("token: device code expired")
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}

		tok, err := RequestToken(ctx, client, code.DeviceCode)
		if err != nil {
			return nil, err
		}

		switch tok.Error {
		case "":
			return tok, nil
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		case "expired_token":
			return nil, fmt.Errorf("token: device code expired")
		case "access_denied":
			return nil, fmt.Errorf("token: authorization denied by user")
		default:
			return nil, fmt.Errorf("token: %s: %s", tok.Error, tok.ErrorDescription)
		}
	}
}
// token.go
