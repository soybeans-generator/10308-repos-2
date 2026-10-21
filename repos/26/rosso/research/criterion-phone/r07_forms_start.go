package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// FormsStart — POST /forms/api/forms/{id}/validations/$start
//
// Starts the form journey. The response body carries the next checkpoint.
func (s *Session) FormsStart(checkpoint string) (string, error) {
	body, err := s.formsPayload()
	if err != nil {
		return "", err
	}
	target := authBase + "/forms/api/forms/" + s.PromptID + "/validations/$start"

	resp, err := s.do(http.MethodPost, target, bytes.NewReader(body), map[string]string{
		"User-Agent":                browserUA,
		"Accept":                    "*/*",
		"Authorization":             "Bearer " + checkpoint,
		"Content-Type":              "application/json",
		"Origin":                    authBase,
		"auth0-forms-location":      authBase + "/u/custom-prompt/" + s.PromptID,
		"auth0-forms-language-hint": "en,en",
		"auth0-forms-state":         s.PromptState,
		"x-requested-with":          "com.criterionchannel",
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var out struct {
		Checkpoint string `json:"checkpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.Checkpoint == "" {
		return "", fmt.Errorf("no checkpoint in validations/$start response")
	}
	return out.Checkpoint, nil
}
