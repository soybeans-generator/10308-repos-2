// 01_login_redirect.go
package main

import "fmt"

// REQUIRED (proved by probe3):
//   - Variant B: purging the __txn_<state> cookie immediately before the
//     callback makes the backend answer 500 "Authentication error" - the
//     cookie is required at the callback, and this request is its only source.
//   - Variant A: self-building the /authorize URL (with our own PKCE pair,
//     no cookie) fails identically at the callback, so there is no way to
//     obtain a working /authorize URL + transaction cookie without this
//     request. 307 -> https://login.criterion.com/authorize?...
func (f *Flow) Request01LoginRedirect() error {
	resp, err := f.get("https://www.criterionchannel.com/login", "https://www.criterionchannel.com/")
	if err != nil {
		return err
	}
	if err := checkStatus(resp, 307, "01 /login"); err != nil {
		return err
	}
	loc := resp.Header.Get("Location")
	if err := drain(resp); err != nil {
		return err
	}
	if loc == "" {
		return fmt.Errorf("01 /login: empty Location")
	}
	f.AuthorizeURL = loc
	return nil
}
// 01_login_redirect.go
