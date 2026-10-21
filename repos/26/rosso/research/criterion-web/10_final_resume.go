// 10_final_resume.go
package main

import "fmt"

// REQUIRED: consumes the fresh resume URL from step 09 and yields the
// authorization code. 302 -> /auth/callback?code=...&state=...
func (f *Flow) Request10FinalResume() error {
	resp, err := f.get(f.ResumeURL, "https://login.criterion.com/u/custom-prompt/"+f.PromptID)
	if err != nil {
		return err
	}
	if err := checkStatus(resp, 302, "10 final resume"); err != nil {
		return err
	}
	loc := resp.Header.Get("Location")
	if err := drain(resp); err != nil {
		return err
	}
	if loc == "" {
		return fmt.Errorf("10 final resume: empty Location")
	}
	f.CallbackURL = resolve(f.ResumeURL, loc)
	if queryValue(f.CallbackURL, "code") == "" {
		return fmt.Errorf("10 final resume: no authorization code in %s", f.CallbackURL)
	}
	return nil
}
// 10_final_resume.go
