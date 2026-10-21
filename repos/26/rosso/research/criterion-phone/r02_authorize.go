package main

import (
	"net/http"
	"net/url"
)

// Authorize — GET https://login.criterion.com/authorize
//
// Starts the Auth0 authorization-code + PKCE flow. The response is a 302 to
// /u/login/identifier?state=... and sets the did/auth0 cookies. Verified by
// diagnostics: only the "auth0" session cookie is a required precondition
// (wiping it => 400 invalid_request at the identifier step); the did /
// did_compat device cookies are optional fingerprinting. Only the state is
// captured here; the identifier page itself does not have to be fetched.
func (s *Session) Authorize() error {
	q := url.Values{}
	q.Set("code_challenge", s.CodeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("scope", scope)
	q.Set("audience", audience)
	q.Set("redirect_uri", redirectURI)

	resp, err := s.do(http.MethodGet, authBase+"/authorize?"+q.Encode(), nil, map[string]string{
		"User-Agent":                browserUA,
		"Accept":                    browserAccept,
		"Upgrade-Insecure-Requests": "1",
		"x-requested-with":          "com.criterionchannel",
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	state, err := queryParam(loc(resp), "state") // /u/login/identifier?state=...
	if err != nil {
		return err
	}
	s.LoginState = state
	return nil
}
