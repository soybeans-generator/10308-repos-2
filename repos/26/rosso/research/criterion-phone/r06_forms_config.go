package main

import (
	"fmt"
	"net/http"
	"net/url"
)

// FormsConfig — GET /forms/api/forms/{promptID}?state=...
//
// Fetches the form definition of the custom prompt. The interesting part is
// the response header auth0-forms-journey-checkpoint: it is the bearer token
// for the next two requests.
func (s *Session) FormsConfig() (string, error) {
	target := authBase + "/forms/api/forms/" + s.PromptID + "?state=" + url.QueryEscape(s.PromptState)

	resp, err := s.do(http.MethodGet, target, nil, map[string]string{
		"User-Agent":                browserUA,
		"Accept":                    "*/*",
		"auth0-forms-location":      authBase + "/u/custom-prompt/" + s.PromptID,
		"auth0-forms-language-hint": "en,en",
		"auth0-forms-state":         s.PromptState,
		"auth0-forms-sdk-version":   "undefined",
		"x-requested-with":          "com.criterionchannel",
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	checkpoint := resp.Header.Get("auth0-forms-journey-checkpoint")
	if checkpoint == "" {
		return "", fmt.Errorf("no journey checkpoint in forms config response")
	}
	return checkpoint, nil
}
