// 04_post_password.go
package main

import (
	"fmt"
	"net/url"
)

// REQUIRED: the credentials. On success 302 -> /authorize/resume?state=P6fc...
// Note that resume URL is SINGLE-USE: the prompt POST is the only way to
// mint a fresh one later (proved by NOPROMPT probe -> access_denied).
func (f *Flow) Request04PostPassword() error {
	form := url.Values{
		"state":    {f.LoginState},
		"username": {f.Username},
		"password": {f.Password},
	}
	resp, err := f.postForm(f.PasswordURL, f.PasswordURL, form)
	if err != nil {
		return err
	}
	if err := checkStatus(resp, 302, "04 post password"); err != nil {
		return err
	}
	loc := resp.Header.Get("Location")
	if err := drain(resp); err != nil {
		return err
	}
	if loc == "" {
		return fmt.Errorf("04 post password: empty Location")
	}
	f.ResumeURL = resolve(f.PasswordURL, loc)
	return nil
}
// 04_post_password.go
