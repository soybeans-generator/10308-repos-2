package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

func urlQueryEscape(v string) string { return url.QueryEscape(v) }

const (
	authBase    = "https://login.criterion.com"
	apiBase     = "https://mw.criterion.com"
	clientID    = "trliIpKF50NOVoCOBBPWO0Z51xjg1VBd"
	redirectURI = "criterion://auth/login/callback"
	audience    = "https://criterionchannel.us.auth0.com/api/v2/"
	scope       = "openid profile email offline_access"

	// The app talks to the API with okhttp, but opens the Auth0 pages in a
	// WebView, so the two endpoints expect different user agents.
	appUA     = "okhttp/5.3.2"
	browserUA = "Mozilla/5.0 (Linux; Android 11; sdk_gphone_x86 Build/RSR1.240422.006; wv) " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/83.0.4103.106 Mobile Safari/537.36"

	browserAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"
)

// Session holds the cookie jar, the PKCE pair and the state values Auth0
// hands out between redirects.
type Session struct {
	HTTP *http.Client

	CodeVerifier  string
	CodeChallenge string

	LoginState  string // "hKFo2SB..."  state of the /u/login/* screens
	ResumeState string // "zklZoN-..."  state of /authorize/resume
	PromptID    string // e.g. "ap_pzamkGkC8AvcxUScERwrqv"
	PromptState string // state of the custom-prompt screen
}

func NewSession() (*Session, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	verifier, challenge, err := newPKCE()
	if err != nil {
		return nil, err
	}
	return &Session{
		HTTP: &http.Client{
			Jar: jar,
			// Redirects are followed manually so the custom
			// "criterion://" deep link can be intercepted.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: 30 * time.Second,
		},
		CodeVerifier:  verifier,
		CodeChallenge: challenge,
	}, nil
}

// do builds and executes a single request. Redirects are never followed
// automatically; every hop is explicit. HTTP >= 400 is turned into an error
// whose message contains a compact digest of the body instead of raw HTML.
func (s *Session) do(method, rawURL string, body io.Reader, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return nil, fmt.Errorf("%s %s: status %d: %s",
			method, redact(rawURL), resp.StatusCode, htmlDigest(string(b)))
	}
	return resp, nil
}

// loc returns the Location header of a redirect response.
func loc(resp *http.Response) string { return resp.Header.Get("Location") }

// queryParam extracts a single query parameter from a (possibly relative) URL.
func queryParam(rawURL, name string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if vals, ok := u.Query()[name]; ok && len(vals) > 0 && vals[0] != "" {
		return vals[0], nil
	}
	return "", fmt.Errorf("missing %q in %s", name, redact(rawURL))
}

// redact strips query strings before using URLs in error messages.
func redact(rawURL string) string {
	if i := strings.Index(rawURL, "?"); i >= 0 {
		return rawURL[:i]
	}
	return rawURL
}

// htmlDigest compresses an HTML error page into the useful bits: the
// <strong>...</strong> error code and the first sentence of the
// error-message block. Non-HTML bodies are whitespace-collapsed and
// truncated.
func htmlDigest(body string) string {
	if !strings.Contains(body, "<html") && !strings.Contains(body, "<body") {
		s := strings.Join(strings.Fields(body), " ")
		if len(s) > 200 {
			s = s[:200] + "..."
		}
		return s
	}
	out := ""
	if i := strings.Index(body, "<strong>"); i >= 0 {
		if j := strings.Index(body[i:], "</strong>"); j > 0 {
			out = strings.TrimSpace(body[i+len("<strong>") : i+j])
			out += ": "
		}
	}
	if i := strings.Index(body, `class="error-message">`); i >= 0 {
		msg := body[i+len(`class="error-message">`):]
		if j := strings.Index(msg, "</p>"); j > 0 {
			msg = msg[:j]
			if k := strings.Index(msg, ". "); k > 0 {
				msg = msg[:k+1]
			}
			msg = strings.Join(strings.Fields(msg), " ")
			out += msg
		}
	}
	if out == "" {
		return "(html error page)"
	}
	return out
}
