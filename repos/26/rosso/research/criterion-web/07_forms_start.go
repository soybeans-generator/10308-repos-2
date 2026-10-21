// 07_forms_start.go
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// REQUIRED (proved by NOSTART probe -> 403 ERR_INVALID_FORM_SESSION on the
// next step): the config token alone is rejected by submissions/; this call
// exchanges it for the submission-authorized checkpoint token.
func (f *Flow) Request07FormsStart() error {
	req, err := http.NewRequest("POST",
		"https://login.criterion.com/forms/api/forms/"+f.PromptID+"/validations/$start",
		strings.NewReader(f.formsMetaDataBody(f.PasswordURL)))
	if err != nil {
		return err
	}
	f.setFormsHeaders(req)

	resp, err := f.do(req)
	if err != nil {
		return err
	}
	if err := checkStatus(resp, 200, "07 forms start"); err != nil {
		return err
	}
	b, err := readAll(resp)
	if err != nil {
		return err
	}
	var out struct {
		Effect struct {
			Checkpoint string `json:"checkpoint"`
		} `json:"effect"`
		Checkpoint string `json:"checkpoint"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return fmt.Errorf("07 forms start: bad JSON: %w", err)
	}
	next := out.Effect.Checkpoint
	if next == "" {
		next = out.Checkpoint
	}
	if next == "" {
		return fmt.Errorf("07 forms start: no checkpoint in %s", b)
	}
	f.CheckpointToken = next
	return nil
}

func (f *Flow) setFormsHeaders(req *http.Request) {
	promptLoc := "https://login.criterion.com/u/custom-prompt/" + f.PromptID
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Referer", promptLoc + "?state=" + urlQueryEscape(f.FormsState))
	req.Header.Set("auth0-forms-language-hint", "en,en")
	req.Header.Set("auth0-forms-location", promptLoc)
	req.Header.Set("auth0-forms-sdk-version", "undefined")
	req.Header.Set("auth0-forms-state", f.FormsState)
	req.Header.Set("Authorization", "Bearer "+f.CheckpointToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://login.criterion.com")
}
// 07_forms_start.go
