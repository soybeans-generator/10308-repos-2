package tubi

import (
   "bytes"
   "crypto/hmac"
   "crypto/rand"
   "crypto/sha256"
   "encoding/base64"
   "encoding/hex"
   "encoding/json"
   "errors"
   "io"
   "log"
   "net/http"
   "net/url"
   "strconv"
   "strings"
   "time"
)

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:158.0) Gecko/20100101 Firefox/158.0"

func AcquireLicense(server *LicenseServer, body []byte) ([]byte, error) {
   req, err := http.NewRequest("POST", server.Url, bytes.NewReader(body))
   if err != nil {
      return nil, err
   }
   req.Header.Set("Accept", "*/*")
   req.Header.Set("Accept-Language", "en-US,en;q=0.5")
   req.Header.Set("User-Agent", userAgent)
   req.Header.Set("Origin", "https://tubitv.com")
   req.Header.Set("Referer", "https://tubitv.com/")
   if server.AuthHeaderKey != "" && server.AuthHeaderValue != "" {
      req.Header.Set(server.AuthHeaderKey, server.AuthHeaderValue)
   }

   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   response, err := io.ReadAll(resp.Body)
   if err != nil {
      return nil, err
   }
   if resp.StatusCode < 200 || resp.StatusCode > 299 {
      return nil, errors.New(resp.Status + ": " + string(response))
   }
   return response, nil
}

// GetToken returns an anonymous device access token.
func GetToken(deviceId string) (string, error) {
   challenge, err := newChallenge()
   if err != nil {
      return "", err
   }

   key, err := getSigningKey(deviceId, challenge)
   if err != nil {
      return "", err
   }

   rawKey, err := base64.StdEncoding.DecodeString(key.Key)
   if err != nil {
      return "", err
   }

   token, err := getAnonymousToken(deviceId, key.Id, makeVerifier(rawKey, challenge), rawKey)
   if err != nil {
      return "", err
   }

   return token.AccessToken, nil
}

func do(req *http.Request) (*http.Response, error) {
   log.Println(req.Method, req.URL)
   return http.DefaultClient.Do(req)
}

func makeVerifier(key []byte, challenge string) string {
   mac := hmac.New(sha256.New, key)
   mac.Write([]byte(challenge))
   return hex.EncodeToString(mac.Sum(nil))[:32]
}

func newChallenge() (string, error) {
   buf := make([]byte, 32)
   if _, err := rand.Read(buf); err != nil {
      return "", err
   }
   return base64.StdEncoding.EncodeToString(buf), nil
}

func sign(key []byte, date, expires, signedHeaders string, body []byte) string {
   sum := sha256.Sum256(body)
   stringToSign := strings.Join([]string{
      "TUBI-HMAC-SHA256",
      date,
      expires,
      signedHeaders,
      hex.EncodeToString(sum[:]),
   }, "\n")

   mac := hmac.New(sha256.New, key)
   mac.Write([]byte(stringToSign))
   return hex.EncodeToString(mac.Sum(nil))
}

type ContentResponse struct {
   VideoResources []VideoResource `json:"video_resources"`
}

func GetContent(contentId int, deviceId, accessToken string) (*ContentResponse, error) {
   target := &url.URL{
      Scheme: "https",
      Host:   "content-cdn.production-public.tubi.io",
      Path:   "/api/v3/content",
   }
   query := url.Values{}
   query.Set("app_id", "tubitv")
   query.Set("platform", "web")
   query.Set("content_id", strconv.Itoa(contentId))
   query.Set("device_id", deviceId)
   query.Set("video_resource_tag", "with_fallback")
   query.Add("limit_resolutions[]", "h264_1080p")
   query.Add("video_resources[]", "hlsv6_widevine_nonclearlead")
   target.RawQuery = query.Encode()

   req, err := http.NewRequest("GET", target.String(), nil)
   if err != nil {
      return nil, err
   }
   req.Header.Set("Accept", "*/*")
   req.Header.Set("Accept-Language", "en-US")
   req.Header.Set("User-Agent", userAgent)
   req.Header.Set("Origin", "https://tubitv.com")
   req.Header.Set("Referer", "https://tubitv.com/")
   req.Header.Set("Accept-Version", "~5.0.0")
   req.Header.Set("X-Capability", `{"content_types":["se"]}`)
   req.Header.Set("Authorization", "Bearer "+accessToken)

   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   if resp.StatusCode < 200 || resp.StatusCode > 299 {
      response, _ := io.ReadAll(resp.Body)
      return nil, errors.New(resp.Status + ": " + string(response))
   }

   var content ContentResponse
   if err := json.NewDecoder(resp.Body).Decode(&content); err != nil {
      return nil, err
   }

   // Return an error if no VideoResources were found in the response
   if len(content.VideoResources) == 0 {
      return nil, errors.New("no video resources found for this content")
   }

   return &content, nil
}

// Widevine returns the first resource that actually carries a license server.
func (c *ContentResponse) Widevine() (*VideoResource, error) {
   for i := range c.VideoResources {
      if c.VideoResources[i].LicenseServer.Url != "" {
         return &c.VideoResources[i], nil
      }
   }
   return nil, errors.New("no widevine license server in response")
}

type LicenseServer struct {
   Url             string `json:"url"`
   HdcpVersion     string `json:"hdcp_version"`
   AuthHeaderKey   string `json:"auth_header_key"`
   AuthHeaderValue string `json:"auth_header_value"`
}

func (*LicenseServer) CachePath() string {
   return "rosso/tubi/LicenseServer"
}

type Manifest struct {
   Url string `json:"url"`
}

type VideoResource struct {
   Type          string        `json:"type"`
   Manifest      Manifest      `json:"manifest"`
   LicenseServer LicenseServer `json:"license_server"`
}

type signingKeyResponse struct {
   Id  string `json:"id"`
   Key string `json:"key"`
}

func getSigningKey(deviceId, challenge string) (*signingKeyResponse, error) {
   body, err := json.Marshal(map[string]string{
      "challenge": challenge,
      "version":   "1.0.0",
      "platform":  "web",
      "device_id": deviceId,
   })
   if err != nil {
      return nil, err
   }

   req, err := http.NewRequest("POST", "https://account.production-public.tubi.io/device/anonymous/signing_key", bytes.NewReader(body))
   if err != nil {
      return nil, err
   }
   req.Header.Set("Accept", "*/*")
   req.Header.Set("Content-Type", "application/json")
   req.Header.Set("User-Agent", userAgent)
   req.Header.Set("Origin", "https://tubitv.com")
   req.Header.Set("Referer", "https://tubitv.com/")

   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   response, err := io.ReadAll(resp.Body)
   if err != nil {
      return nil, err
   }
   if resp.StatusCode < 200 || resp.StatusCode > 299 {
      return nil, errors.New(resp.Status + ": " + string(response))
   }

   var key signingKeyResponse
   if err := json.Unmarshal(response, &key); err != nil {
      return nil, err
   }
   return &key, nil
}

type tokenResponse struct {
   AccessToken  string `json:"access_token"`
   RefreshToken string `json:"refresh_token"`
   ExpiresIn    int    `json:"expires_in"`
}

func getAnonymousToken(deviceId, id, verifier string, key []byte) (*tokenResponse, error) {
   body, err := json.Marshal(map[string]string{
      "verifier":  verifier,
      "id":        id,
      "platform":  "web",
      "device_id": deviceId,
   })
   if err != nil {
      return nil, err
   }

   date := time.Now().UTC().Format("20060102T150405Z")
   expires := "30"
   signedHeaders := "content-type"

   target := &url.URL{
      Scheme: "https",
      Host:   "account.production-public.tubi.io",
      Path:   "/device/anonymous/token",
   }
   query := url.Values{}
   query.Set("X-Tubi-Algorithm", "TUBI-HMAC-SHA256")
   query.Set("X-Tubi-Date", date)
   query.Set("X-Tubi-Expires", expires)
   query.Set("X-Tubi-SignedHeaders", signedHeaders)
   query.Set("X-Tubi-Signature", sign(key, date, expires, signedHeaders, body))
   target.RawQuery = query.Encode()

   req, err := http.NewRequest("POST", target.String(), bytes.NewReader(body))
   if err != nil {
      return nil, err
   }
   req.Header.Set("Accept", "*/*")
   req.Header.Set("Content-Type", "application/json")
   req.Header.Set("User-Agent", userAgent)
   req.Header.Set("Origin", "https://tubitv.com")
   req.Header.Set("Referer", "https://tubitv.com/")

   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   response, err := io.ReadAll(resp.Body)
   if err != nil {
      return nil, err
   }
   if resp.StatusCode < 200 || resp.StatusCode > 299 {
      return nil, errors.New(resp.Status + ": " + string(response))
   }

   var token tokenResponse
   if err := json.Unmarshal(response, &token); err != nil {
      return nil, err
   }
   return &token, nil
}
