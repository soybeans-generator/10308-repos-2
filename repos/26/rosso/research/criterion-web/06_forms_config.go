// 06_forms_config.go
package main

import (
	"fmt"
	"net/http"
)

// REQUIRED (proved by NOCONFIG probe -> 403 ERR_INVALID_FORM_SESSION):
// the auth0-forms-journey-checkpoint response header is the initial
// bearer token for the forms API.
func (f *Flow) Request06FormsConfig() error {
	promptLoc := "https://login.criterion.com/u/custom-prompt/" + f.PromptID
	target := promptLoc + "?state=" + urlQueryEscape(f.FormsState)
	req, err := http.NewRequest("GET", "https://login.criterion.com/forms/api/forms/"+
		f.PromptID+"?state="+urlQueryEscape(f.FormsState), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Referer", target)
	req.Header.Set("auth0-forms-language-hint", "en,en")
	req.Header.Set("auth0-forms-location", promptLoc)
	req.Header.Set("auth0-forms-sdk-version", "undefined")
	req.Header.Set("auth0-forms-state", f.FormsState)

	resp, err := f.do(req)
	if err != nil {
		return err
	}
	if err := checkStatus(resp, 200, "06 forms config"); err != nil {
		return err
	}
	token := resp.Header.Get("auth0-forms-journey-checkpoint")
	if err := drain(resp); err != nil {
		return err
	}
	if token == "" {
		return fmt.Errorf("06 forms config: no auth0-forms-journey-checkpoint header")
	}
	f.CheckpointToken = token
	return nil
}
// 06_forms_config.go
