package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// LoginPassword — POST https://login.criterion.com/u/login/password
//
// Submits the credentials. On success Auth0 updates the session cookies and
// redirects to /authorize/resume?state=...; that state is stored for the two
// later /authorize/resume calls. A 200 instead of a 302 means the
// credentials were rejected.
func (s *Session) LoginPassword(email, password string) error {
	target := authBase + "/u/login/password?state=" + url.QueryEscape(s.LoginState)

	form := url.Values{}
	form.Set("state", s.LoginState)
	form.Set("username", email)
	form.Set("password", password)

	resp, err := s.do(http.MethodPost, target, strings.NewReader(form.Encode()), map[string]string{
		"User-Agent":       browserUA,
		"Accept":           browserAccept,
		"Content-Type":     "application/x-www-form-urlencoded",
		"Origin":           authBase,
		"Referer":          authBase + "/u/login/identifier?state=" + url.QueryEscape(s.LoginState),
		"x-requested-with": "com.criterionchannel",
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	next := loc(resp)
	if next == "" {
		return fmt.Errorf("login rejected (check credentials)")
	}
	resume, err := queryParam(next, "state")
	if err != nil {
		return err
	}
	s.ResumeState = resume
	return nil
}
