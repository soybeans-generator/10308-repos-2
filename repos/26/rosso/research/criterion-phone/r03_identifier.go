package main

import (
	"net/http"
	"net/url"
	"strings"
)

// LoginIdentifier — POST https://login.criterion.com/u/login/identifier
//
// Submits the e-mail address (step 1 of the universal login). The server
// answers with a 302 to /u/login/password; no new state or cookies are
// issued, so LoginState keeps being used.
func (s *Session) LoginIdentifier(email string) error {
	target := authBase + "/u/login/identifier?state=" + url.QueryEscape(s.LoginState)

	form := url.Values{}
	form.Set("state", s.LoginState)
	form.Set("username", email)
	form.Set("js-available", "true")
	form.Set("webauthn-available", "false")
	form.Set("is-brave", "false")
	form.Set("webauthn-platform-available", "false")

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

	// Next hop must be the password screen.
	_, err = queryParam(loc(resp), "state")
	return err
}
