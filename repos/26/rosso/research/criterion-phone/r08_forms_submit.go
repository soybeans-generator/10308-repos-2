package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// FormsSubmit — POST /forms/api/forms/{id}/submissions/
//
// Submits the (field-less) form. The response must be an ENDING_SCREEN with
// resumeFlow=true — only then does the POST on the custom-prompt page
// continue the authorize flow.
func (s *Session) FormsSubmit(checkpoint string) error {
	body, err := s.formsPayload()
	if err != nil {
		return err
	}
	target := authBase + "/forms/api/forms/" + s.PromptID + "/submissions/"

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
		return err
	}
	defer resp.Body.Close()

	var out struct {
		Effect struct {
			Type   string `json:"type"`
			Screen struct {
				ResumeFlow bool `json:"resumeFlow"`
			} `json:"screen"`
		} `json:"effect"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	if out.Effect.Type != "ENDING_SCREEN" {
		return fmt.Errorf("unexpected form effect type: %q", out.Effect.Type)
	}
	if !out.Effect.Screen.ResumeFlow {
		return fmt.Errorf("form did not request resumeFlow")
	}
	return nil
}
