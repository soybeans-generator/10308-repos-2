// 05_resume_to_prompt.go
package main

import (
	"fmt"
	"net/url"
	"strings"
)

// REQUIRED (proved by probe5):
//   - Variant E1: constructing the prompt URL with the resume state (P6fc...)
//     -> forms config 403s: the forms API validates that the state is a
//     custom-prompt transaction state, and this request is the only thing
//     that mints one.
//   - Variant E2: same rejection with the login transaction state (hKFo...),
//     so it is not merely a type-check on the state format.
// Note this is NOT redundant with the second /authorize/resume: resume #1
// mints the prompt transaction, resume #2 mints the authorization code.
// 302 -> /u/custom-prompt/<id>?state=...
func (f *Flow) Request05ResumeToPrompt() error {
	resp, err := f.get(f.ResumeURL, f.PasswordURL)
	if err != nil {
		return err
	}
	if err := checkStatus(resp, 302, "05 resume"); err != nil {
		return err
	}
	loc := resp.Header.Get("Location")
	if err := drain(resp); err != nil {
		return err
	}
	if loc == "" {
		return fmt.Errorf("05 resume: empty Location")
	}
	promptURL := resolve(f.ResumeURL, loc)
	f.FormsState = queryValue(promptURL, "state")
	if u, err := url.Parse(promptURL); err == nil {
		f.PromptID = strings.TrimPrefix(u.Path, "/u/custom-prompt/")
	}
	if f.FormsState == "" || f.PromptID == "" {
		return fmt.Errorf("05 resume: could not parse %s", promptURL)
	}
	return nil
}
// 05_resume_to_prompt.go
