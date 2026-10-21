// main.go
package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

func main() {
	email := os.Getenv("CRITERION_EMAIL")
	password := os.Getenv("CRITERION_PASSWORD")
	if email == "" || password == "" {
		fmt.Fprintln(os.Stderr, "usage: CRITERION_EMAIL=... CRITERION_PASSWORD=... criterion-login")
		os.Exit(1)
	}
	if err := run(email, password); err != nil {
		fmt.Fprintln(os.Stderr, "login failed:", err)
		os.Exit(1)
	}
}

// run performs the minimal 10-request login. Every step has been proven
// required empirically; see the per-function comments for what happens
// when each is skipped.
func run(email, password string) error {
	s, err := NewSession()
	if err != nil {
		return err
	}

	// 1. Start the PKCE authorize flow -> LoginState.
	if err := s.Authorize(); err != nil {
		return fmt.Errorf("authorize: %w", err)
	}

	// 2. Submit the e-mail address. Required: this is the step that
	// establishes the Auth0 login session cookie.
	if err := s.LoginIdentifier(email); err != nil {
		return fmt.Errorf("identifier: %w", err)
	}

	// 3. Submit the password -> ResumeState.
	if err := s.LoginPassword(email, password); err != nil {
		return fmt.Errorf("password: %w", err)
	}

	// 4. /authorize/resume #1 -> custom prompt.
	next, err := s.AuthorizeResume()
	if err != nil {
		return fmt.Errorf("resume: %w", err)
	}

	// The tenant shows a custom prompt screen on every login (verified by
	// diagnostics; it is not a one-time consent), so the branch below is
	// part of the mandatory flow.
	if !strings.HasPrefix(next, redirectURI) {
		if err := s.parsePromptURL(next); err != nil {
			return fmt.Errorf("prompt: %w", err)
		}

		// 5-7. Complete the form journey through the forms API.
		cp, err := s.FormsConfig()
		if err != nil {
			return fmt.Errorf("forms config: %w", err)
		}
		if cp, err = s.FormsStart(cp); err != nil {
			return fmt.Errorf("forms start: %w", err)
		}
		if err := s.FormsSubmit(cp); err != nil {
			return fmt.Errorf("forms submit: %w", err)
		}

		// 8. Accept the prompt -> back to /authorize/resume.
		if err := s.AcceptCustomPrompt(); err != nil {
			return fmt.Errorf("accept prompt: %w", err)
		}

		// 9. /authorize/resume #2 -> criterion://auth/login/callback?code=...
		if next, err = s.AuthorizeResume(); err != nil {
			return fmt.Errorf("resume: %w", err)
		}
	}

	code, err := queryParam(next, "code")
	if err != nil {
		return fmt.Errorf("callback: %w", err)
	}

	// 10. Exchange the code for tokens.
	tok, err := s.ExchangeCode(code)
	if err != nil {
		return fmt.Errorf("token: %w", err)
	}

	fmt.Println("access_token :", tok.AccessToken)
	fmt.Println("refresh_token:", tok.RefreshToken)
	fmt.Println("id_token     :", tok.IDToken)
	fmt.Printf("expires_in   : %ds\n", tok.ExpiresIn)
	return nil
}

// parsePromptURL extracts prompt id and state from a
// /u/custom-prompt/{id}?state=... location.
func (s *Session) parsePromptURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 3 || parts[0] != "u" || parts[1] != "custom-prompt" {
		return fmt.Errorf("unexpected resume location %q", raw)
	}
	s.PromptID = parts[2]
	state, err := queryParam(raw, "state")
	if err != nil {
		return err
	}
	s.PromptState = state
	return nil
}

// main.go
