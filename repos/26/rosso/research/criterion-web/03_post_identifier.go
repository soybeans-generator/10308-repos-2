// 03_post_identifier.go
package main

import (
	"fmt"
	"net/url"
)

// REQUIRED (proved by probe): posting credentials straight to the password
// URL makes the later prompt POST 404 - this request creates the server-side
// session state the whole flow depends on.
func (f *Flow) Request03PostIdentifier() error {
	form := url.Values{
		"state":                      {f.LoginState},
		"username":                   {f.Username},
		"js-available":               {"true"},
		"webauthn-available":         {"true"},
		"is-brave":                   {"false"},
		"webauthn-platform-available": {"false"},
	}
	resp, err := f.postForm(f.IdentifierURL, f.IdentifierURL, form)
	if err != nil {
		return err
	}
	if err := checkStatus(resp, 302, "03 post identifier"); err != nil {
		return err
	}
	loc := resp.Header.Get("Location")
	if err := drain(resp); err != nil {
		return err
	}
	if loc == "" {
		return fmt.Errorf("03 post identifier: empty Location")
	}
	f.PasswordURL = resolve(f.IdentifierURL, loc)
	return nil
}
// 03_post_identifier.go
