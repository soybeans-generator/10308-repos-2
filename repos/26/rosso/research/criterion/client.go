// client.go
package criterion

import (
   "net/http"
   "time"
)

const (
   // LoginBaseURL is the Auth0 tenant that runs the device flow.
   LoginBaseURL = "https://login.criterion.com"
   // ClientID is the app's public OAuth client id.
   ClientID = "trliIpKF50NOVoCOBBPWO0Z51xjg1VBd"
   // Scope is what the app requests.
   Scope = "openid profile email offline_access"
   // UserAgent mimics the Android client.
   UserAgent = "okhttp/5.3.2"
)

// NewClient returns the http.Client used by the login requests. Callers should
// reuse one instance for the whole flow, though nothing is carried between the
// two calls except the device code itself.
//
// No cookie jar: okhttp (the real client) has no cookie store, and the HAR
// shows both /oauth/device/code and /oauth/token with an empty cookie list.
func NewClient() *http.Client {
   return &http.Client{Timeout: 30 * time.Second}
}

// client.go
