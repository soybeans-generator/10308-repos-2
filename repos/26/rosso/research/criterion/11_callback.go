// 11_callback.go
package main

import (
	"fmt"
	"net/url"
)

// REQUIRED: the web app exchanges the code server-side and sets the
// __session + criterion_dz_logged_in cookies. 307 -> "/".
func (f *Flow) Request11Callback() error {
	resp, err := f.get(f.CallbackURL, "")
	if err != nil {
		return err
	}
	if err := checkStatus(resp, 307, "11 callback"); err != nil {
		return err
	}
	if err := drain(resp); err != nil {
		return err
	}
	u, _ := url.Parse("https://www.criterionchannel.com/")
	for _, c := range f.Client.Jar.Cookies(u) {
		if c.Name == "__session" {
			return nil
		}
	}
	return fmt.Errorf("11 callback: no __session cookie was set")
}
// 11_callback.go
