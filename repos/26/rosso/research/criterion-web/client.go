// client.go
package main

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:158.0) Gecko/20100101 Firefox/158.0"

// Flow holds the shared cookie-jar client and the values handed
// from one request to the next.
//
// All 11 requests below are experimentally confirmed REQUIRED
// (probed 2026-10-21): each either holds unique state or performs a
// server-side transition that no other request can substitute.
type Flow struct {
	Client   *http.Client
	Username string
	Password string

	AuthorizeURL    string // /authorize?... from the /login redirect
	IdentifierURL   string // /u/login/identifier?state=...
	LoginState      string // Auth0 transaction state (hKFo...)
	PasswordURL     string // /u/login/password?state=...
	ResumeURL       string // /authorize/resume?state=P6fc... (single-use!)
	PromptID        string // ap_... (observed stable, but always re-read)
	FormsState      string // state of the custom-prompt page
	CheckpointToken string // bearer token for the forms API
	CallbackURL     string // /auth/callback?code=...
}

func NewFlow(username, password string) *Flow {
	jar, _ := cookiejar.New(nil)
	return &Flow{
		Client: &http.Client{
			Jar: jar,
			// Every redirect hop is an explicit request in its own file;
			// auto-following would collapse several of the 11 requests.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Username: username,
		Password: password,
	}
}

func (f *Flow) do(req *http.Request) (*http.Response, error) {
	return f.Client.Do(req)
}

func (f *Flow) get(target, referer string) (*http.Response, error) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
	return f.do(req)
}

func (f *Flow) postForm(target, referer string, form url.Values) (*http.Response, error) {
	req, err := http.NewRequest("POST", target, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://login.criterion.com")
	req.Header.Set("Referer", referer)
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	return f.do(req)
}

func checkStatus(resp *http.Response, want int, step string) error {
	if resp.StatusCode != want {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		resp.Body.Close()
		return &StatusError{Step: step, Want: want, Got: resp.StatusCode, Body: string(b)}
	}
	return nil
}

type StatusError struct {
	Step          string
	Want, Got     int
	Body          string
}

func (e *StatusError) Error() string {
	return e.Step + ": got " + itoa(e.Got) + " (want " + itoa(e.Want) + "): " + e.Body
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func drain(resp *http.Response) error {
	_, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return err
}

func readAll(resp *http.Response) ([]byte, error) {
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	return b, err
}

func resolve(base, location string) string {
	b, err := url.Parse(base)
	if err != nil {
		return location
	}
	l, err := url.Parse(location)
	if err != nil {
		return location
	}
	return b.ResolveReference(l).String()
}

func queryValue(rawURL, name string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Query().Get(name)
}

// formsMetaDataBody builds the metaData JSON payload the Auth0 forms SDK
// sends with the /validations/$start and /submissions/ calls.
func (f *Flow) formsMetaDataBody(referer string) string {
	pathname := "/u/custom-prompt/" + f.PromptID
	href := "https://login.criterion.com" + pathname + "?state=" + f.FormsState
	return `{"formData":{},"metaData":{"navigator":{"userAgent":"` + userAgent +
		`","language":"en-US"},"navigation":{"referer":"` + referer +
		`","location":{"protocol":"https:","hostname":"login.criterion.com","port":"","host":"login.criterion.com","pathname":"` + pathname +
		`","search":"?state=` + f.FormsState +
		`","searchParams":{"state":"` + f.FormsState +
		`"},"hash":"","href":"` + href +
		`"},"analytics":{"ga":{}}},"view":{"screen":{"height":900,"width":1600},"window":{"height":698,"width":1333}}}}`
}
// client.go
