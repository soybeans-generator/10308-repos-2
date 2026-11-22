// oauth.go KEEP THIS LINE
package unext

import (
   "bytes"
   "crypto/sha256"
   "encoding/base64"
   "encoding/json"
   "fmt"
   "io"
   "log"
   "net/http"
   "net/url"
   "strings"
   "time"
)

// Japan
const x_forwarded_for = "133.0.0.0"

func GeneratePKCE() string {
   return base64.RawURLEncoding.EncodeToString([]byte(time.Now().String()))
}

// Step2Login authenticates with email/password and returns the post_auth_endpoint
func Step2Login(email, password, challengeID string) (string, error) {
   loginURL := "https://oauth.unext.jp/oauth2/login"
   body := map[string]any{
      "id":           email,
      "password":     password,
      "challenge_id": challengeID,
      "scope": []string{
         "offline",
         "unext",
      },
   }
   jsonBody, err := json.Marshal(body)
   if err != nil {
      return "", fmt.Errorf("step2: marshalling body: %w", err)
   }
   req, err := http.NewRequest("POST", loginURL, bytes.NewReader(jsonBody))
   if err != nil {
      return "", fmt.Errorf("step2: creating request: %w", err)
   }
   req.Header.Set("x-forwarded-for", x_forwarded_for)
   resp, err := clientDo(req)
   if err != nil {
      return "", fmt.Errorf("step2: sending request: %w", err)
   }
   defer resp.Body.Close()

   if resp.StatusCode != http.StatusOK {
      return "", fmt.Errorf("step2: expected 200, got %d", resp.StatusCode)
   }

   var loginResp LoginResponse
   if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
      return "", fmt.Errorf("step2: parsing response: %w", err)
   }

   if loginResp.PostAuthEndpoint == "" {
      return "", fmt.Errorf("step2: post_auth_endpoint is empty")
   }

   return loginResp.PostAuthEndpoint, nil
}

// Step3GetAuthCode sends the code_challenge to the post_auth_endpoint and
// extracts the authorization code from the 302 redirect Location header.
func Step3GetAuthCode(postAuthEndpoint string, auth *AuthState) (string, error) {
   fullURL := "https://oauth.unext.jp" + postAuthEndpoint
   h := sha256.Sum256([]byte(auth.CodeVerifier))
   challenge := base64.RawURLEncoding.EncodeToString(h[:])
   form := url.Values{}
   form.Set("code_challenge", challenge)
   form.Set("code_challenge_method", "S256")
   req, err := http.NewRequest("POST", fullURL, strings.NewReader(form.Encode()))
   if err != nil {
      return "", fmt.Errorf("step3: creating request: %w", err)
   }
   req.Header.Set("content-type", "application/x-www-form-urlencoded")
   resp, err := clientDoNoRedirect(req)
   if err != nil {
      return "", fmt.Errorf("step3: sending request: %w", err)
   }
   defer resp.Body.Close()

   if _, err := io.Copy(io.Discard, resp.Body); err != nil {
      return "", fmt.Errorf("step3: draining response body: %w", err)
   }

   if resp.StatusCode != http.StatusFound {
      return "", fmt.Errorf("step3: expected 302, got %d", resp.StatusCode)
   }

   locURL, err := resp.Location()
   if err != nil {
      return "", fmt.Errorf("step3: getting Location header: %w", err)
   }

   code := locURL.Query().Get("code")
   if code == "" {
      return "", fmt.Errorf("step3: code not found in Location: %s", locURL)
   }

   return code, nil
}

func clientDo(req *http.Request) (*http.Response, error) {
   log.Println(req.Method, req.URL)
   return http.DefaultClient.Do(req)
}

func clientDoNoRedirect(req *http.Request) (*http.Response, error) {
   log.Println(req.Method, req.URL)
   client := &http.Client{
      CheckRedirect: func(*http.Request, []*http.Request) error {
         return http.ErrUseLastResponse
      },
   }
   return client.Do(req)
}

// AuthState holds the challenge_id and PKCE verifier produced by Step1.
type AuthState struct {
   ChallengeID  string
   CodeVerifier string
}

// Step1GetChallenge performs the initial GET to /oauth2/auth and extracts
// the challenge_id from the 302 redirect Location header.
func Step1GetChallenge() (*AuthState, error) {
   baseURL := "https://oauth.unext.jp/oauth2/auth"
   pkce := GeneratePKCE()
   params := url.Values{}
   params.Set("nonce", pkce)
   params.Set("state", pkce)
   params.Set("scope", "offline unext")
   params.Set("response_type", "code")
   params.Set("client_id", "unextAndroidApp")
   params.Set("redirect_uri", "jp.unext://page=oauth_callback")
   req, err := http.NewRequest("GET", baseURL+"?"+params.Encode(), nil)
   if err != nil {
      return nil, fmt.Errorf("step1: creating request: %w", err)
   }
   resp, err := clientDoNoRedirect(req)
   if err != nil {
      return nil, fmt.Errorf("step1: sending request: %w", err)
   }
   defer resp.Body.Close()

   if _, err := io.Copy(io.Discard, resp.Body); err != nil {
      return nil, fmt.Errorf("step1: draining response body: %w", err)
   }

   if resp.StatusCode != http.StatusFound {
      return nil, fmt.Errorf("step1: expected 302, got %d", resp.StatusCode)
   }

   locURL, err := resp.Location()
   if err != nil {
      return nil, fmt.Errorf("step1: getting Location header: %w", err)
   }

   challengeID := locURL.Query().Get("challenge_id")
   if challengeID == "" {
      return nil, fmt.Errorf("step1: challenge_id not found in Location: %s", locURL)
   }

   return &AuthState{
      ChallengeID:  challengeID,
      CodeVerifier: pkce,
   }, nil
}

// LoginResponse is the JSON returned by /oauth2/login.
type LoginResponse struct {
   PostAuthEndpoint string `json:"post_auth_endpoint"`
}

// TokenResponse is the JSON returned by /oauth2/token.
type TokenResponse struct {
   AccessToken  string `json:"access_token"`
   ExpiresIn    int    `json:"expires_in"`
   RefreshToken string `json:"refresh_token"`
   Scope        string `json:"scope"`
   TokenType    string `json:"token_type"`
}

// Step4GetToken exchanges the authorization code for access and refresh tokens.
func Step4GetToken(authCode string, auth *AuthState) (*TokenResponse, error) {
   tokenURL := "https://oauth.unext.jp/oauth2/token"
   form := url.Values{}
   form.Set("code", authCode)
   form.Set("code_verifier", auth.CodeVerifier)
   form.Set("grant_type", "authorization_code")
   form.Set("client_id", "unextAndroidApp")
   form.Set("redirect_uri", "jp.unext://page=oauth_callback")
   req, err := http.NewRequest("POST", tokenURL, strings.NewReader(form.Encode()))
   if err != nil {
      return nil, fmt.Errorf("step4: creating request: %w", err)
   }
   req.Header.Set("content-type", "application/x-www-form-urlencoded")
   resp, err := clientDo(req)
   if err != nil {
      return nil, fmt.Errorf("step4: sending request: %w", err)
   }
   defer resp.Body.Close()

   if resp.StatusCode != http.StatusOK {
      return nil, fmt.Errorf("step4: expected 200, got %d", resp.StatusCode)
   }

   var tokenResp TokenResponse
   if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
      return nil, fmt.Errorf("step4: parsing response: %w", err)
   }

   return &tokenResp, nil
}

func (*TokenResponse) CachePath() string {
   return "rosso/unext/TokenResponse"
}

// Refresh exchanges the receiver's RefreshToken for a new set of tokens
// and writes the result back into the receiver.
func (t *TokenResponse) Refresh() error {
   tokenURL := "https://oauth.unext.jp/oauth2/token"
   form := url.Values{}
   form.Set("refresh_token", t.RefreshToken)
   form.Set("grant_type", "refresh_token")
   form.Set("client_id", "unextAndroidApp")
   req, err := http.NewRequest("POST", tokenURL, strings.NewReader(form.Encode()))
   if err != nil {
      return fmt.Errorf("refresh: creating request: %w", err)
   }
   req.Header.Set("content-type", "application/x-www-form-urlencoded")
   resp, err := clientDo(req)
   if err != nil {
      return fmt.Errorf("refresh: sending request: %w", err)
   }
   defer resp.Body.Close()

   if resp.StatusCode != http.StatusOK {
      return fmt.Errorf("refresh: expected 200, got %d", resp.StatusCode)
   }

   var newToken TokenResponse
   if err := json.NewDecoder(resp.Body).Decode(&newToken); err != nil {
      return fmt.Errorf("refresh: parsing response: %w", err)
   }

   // Write the new tokens back into the receiver.
   *t = newToken
   return nil
}

// oauth.go KEEP THIS LINE
