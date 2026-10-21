// 08_forms_submission.go
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// REQUIRED (proved by NOFORMS probe -> callback error "The form was not
// completed"): this is the server-side completion marker for the prompt.
func (f *Flow) Request08FormsSubmission() error {
	req, err := http.NewRequest("POST",
		"https://login.criterion.com/forms/api/forms/"+f.PromptID+"/submissions/",
		strings.NewReader(f.formsMetaDataBody(f.PasswordURL)))
	if err != nil {
		return err
	}
	f.setFormsHeaders(req)

	resp, err := f.do(req)
	if err != nil {
		return err
	}
	if err := checkStatus(resp, 200, "08 forms submission"); err != nil {
		return err
	}
	b, err := readAll(resp)
	if err != nil {
		return err
	}
	var out struct {
		Effect struct {
			Type   string `json:"type"`
			Screen struct {
				ResumeFlow bool `json:"resumeFlow"`
			} `json:"screen"`
		} `json:"effect"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return fmt.Errorf("08 forms submission: bad JSON: %w", err)
	}
	if out.Effect.Type != "ENDING_SCREEN" {
		return fmt.Errorf("08 forms submission: unexpected effect %q", out.Effect.Type)
	}
	if !out.Effect.Screen.ResumeFlow {
		return fmt.Errorf("08 forms submission: flow did not resume")
	}
	return nil
}
// 08_forms_submission.go
