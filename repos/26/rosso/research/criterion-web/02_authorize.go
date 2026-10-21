// 02_authorize.go
package main

import "fmt"

// REQUIRED (proved by probe4):
//   - Variant D: posting the identifier form with a fabricated transaction
//     state is rejected with 400 - the state is server-validated and this
//     request is its only source.
//   - Variant C: purging the did/did_compat/auth0/auth0_compat cookies set
//     by this request makes the identifier POST still succeed, but the
//     password POST 404s - the cookies hold the login session that
//     /u/login/password requires.
// 302 -> /u/login/identifier?state=...
func (f *Flow) Request02Authorize() error {
	resp, err := f.get(f.AuthorizeURL, "https://www.criterionchannel.com/")
	if err != nil {
		return err
	}
	if err := checkStatus(resp, 302, "02 /authorize"); err != nil {
		return err
	}
	loc := resp.Header.Get("Location")
	if err := drain(resp); err != nil {
		return err
	}
	if loc == "" {
		return fmt.Errorf("02 /authorize: empty Location")
	}
	f.IdentifierURL = resolve(f.AuthorizeURL, loc)
	f.LoginState = queryValue(f.IdentifierURL, "state")
	if f.LoginState == "" {
		return fmt.Errorf("02 /authorize: no state in %s", f.IdentifierURL)
	}
	return nil
}
// 02_authorize.go
