package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// TokenResponse is the payload of POST /oauth/token.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// ExchangeCode — POST https://login.criterion.com/oauth/token
//
// Final request of the flow: the authorization code plus the PKCE verifier
// are exchanged for the tokens. This call is made by the app itself
// (okhttp user agent), not by the WebView.
func (s *Session) ExchangeCode(code string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("code_verifier", s.CodeVerifier)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)

	resp, err := s.do(http.MethodPost, authBase+"/oauth/token", strings.NewReader(form.Encode()), map[string]string{
		"User-Agent":   appUA,
		"Content-Type": "application/x-www-form-urlencoded",
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	out := new(TokenResponse)
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return nil, err
	}
	return out, nil
}
