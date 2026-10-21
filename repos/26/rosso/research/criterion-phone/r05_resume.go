package main

import (
	"fmt"
	"net/http"
	"net/url"
)

// AuthorizeResume — GET https://login.criterion.com/authorize/resume
//
// Generic hop over /authorize/resume, called twice:
//
//  1. right after the credentials: redirects to the custom prompt
//     (/u/custom-prompt/{id}?state=...)
//  2. after accepting the prompt: redirects to the app deep link
//     criterion://auth/login/callback?code=...
//
// It only returns the Location header; the caller decides what to do with it.
func (s *Session) AuthorizeResume() (string, error) {
	target := authBase + "/authorize/resume?state=" + url.QueryEscape(s.ResumeState)

	resp, err := s.do(http.MethodGet, target, nil, map[string]string{
		"User-Agent":                browserUA,
		"Accept":                    browserAccept,
		"Upgrade-Insecure-Requests": "1",
		"x-requested-with":          "com.criterionchannel",
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	next := loc(resp)
	if next == "" {
		return "", fmt.Errorf("authorize/resume returned no location")
	}
	return next, nil
}
