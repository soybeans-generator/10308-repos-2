package main

import (
	"net/http"
	"net/url"
	"strings"
)

// AcceptCustomPrompt — POST https://login.criterion.com/u/custom-prompt/{id}
//
// Accepts the custom prompt (the form has no fields, only the state is
// posted). The server redirects back to /authorize/resume, which now yields
// the authorization code.
func (s *Session) AcceptCustomPrompt() error {
	target := authBase + "/u/custom-prompt/" + s.PromptID + "?state=" + url.QueryEscape(s.PromptState)

	form := url.Values{}
	form.Set("state", s.PromptState)

	resp, err := s.do(http.MethodPost, target, strings.NewReader(form.Encode()), map[string]string{
		"User-Agent":       browserUA,
		"Accept":           browserAccept,
		"Content-Type":     "application/x-www-form-urlencoded",
		"Origin":           authBase,
		"Referer":          target,
		"x-requested-with": "com.criterionchannel",
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Next hop: /authorize/resume?state=... (same state as before).
	_, err = queryParam(loc(resp), "state")
	return err
}
