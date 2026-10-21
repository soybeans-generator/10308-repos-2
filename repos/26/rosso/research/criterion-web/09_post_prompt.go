// 09_post_prompt.go
package main

import (
	"fmt"
	"net/url"
)

// REQUIRED (proved by NOPROMPT probe -> access_denied "couldn't find your
// session"): the resume URL from step 04 is single-use; this POST is the
// only way to obtain a fresh /authorize/resume state.
func (f *Flow) Request09PostPrompt() error {
	target := "https://login.criterion.com/u/custom-prompt/" + f.PromptID +
		"?state=" + urlQueryEscape(f.FormsState)
	form := url.Values{"state": {f.FormsState}}
	resp, err := f.postForm(target, target, form)
	if err != nil {
		return err
	}
	if err := checkStatus(resp, 302, "09 post prompt"); err != nil {
		return err
	}
	loc := resp.Header.Get("Location")
	if err := drain(resp); err != nil {
		return err
	}
	if loc == "" {
		return fmt.Errorf("09 post prompt: empty Location")
	}
	f.ResumeURL = resolve(target, loc)
	return nil
}
// 09_post_prompt.go
