// client.go KEEP THIS LINE
package hboMax

import (
   "bytes"
   "encoding/json"
   "errors"
   "fmt"
   "io"
   "log"
   "net/http"
   "net/url"
   "strings"
)

const Markets = "amer apac emea latam"

const device_info = "hboMax/hboMax (hboMax/hboMax; hboMax/hboMax; hboMax/hboMax)"

const disco_client = "hboMax:hboMax:hboMax:hboMax"

const disco_params = "hboMax=hboMax"

// doReq handles executing the HTTP request and logging the method/URL
func doReq(req *http.Request) (*http.Response, error) {
   log.Println(req.Method, req.URL)
   return http.DefaultClient.Do(req)
}

// entity_request is the single JSON:API fetch used by every CMS endpoint.
func entity_request(token string, endpoint *url.URL) ([]*Entity, error) {
   // Scheme
   endpoint.Scheme = "https"
   // Host
   endpoint.Host = "default.prd.api.hbomax.com"
   // RawQuery
   query := endpoint.Query()
   query.Set("include", "default")
   endpoint.RawQuery = query.Encode()

   req, err := http.NewRequest(http.MethodGet, endpoint.String(), nil)
   if err != nil {
      return nil, err
   }
   req.Header.Set("authorization", "Bearer "+token)
   req.Header.Set("x-disco-params", disco_params)
   req.Header.Set("x-disco-client", disco_client)
   req.Header.Set("x-device-info", device_info)

   resp, err := doReq(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   var result struct {
      Errors   APIErrors `json:"errors"`
      Included []*Entity `json:"included"`
   }
   err = json.NewDecoder(resp.Body).Decode(&result)
   if err != nil {
      return nil, err
   }
   if len(result.Errors) > 0 {
      return nil, result.Errors
   }
   return result.Included, nil
}

func PlayReadyRequest(token, editId string) (*Playback, error) {
   return playback_request(token, editId, "playready")
}

func WidevineRequest(token, editId string) (*Playback, error) {
   return playback_request(token, editId, "widevine")
}

func playback_request(token, edit_id, drm string) (*Playback, error) {
   body, err := json.Marshal(map[string]any{
      "editId":               edit_id,
      "consumptionType":      "streaming",
      "appBundle":            "",         // required
      "applicationSessionId": "",         // required
      "firstPlay":            false,      // required
      "gdpr":                 false,      // required
      "playbackSessionId":    "",         // required
      "userPreferences":      struct{}{}, // required
      "capabilities": map[string]any{
         "contentProtection": map[string]any{
            "contentDecryptionModules": []any{
               map[string]string{
                  "drmKeySystem": drm,
               },
            },
         },
         "manifests": map[string]any{
            "formats": map[string]any{
               "dash": struct{}{}, // required
            }, // required
         }, // required
      }, // required
      "deviceInfo": map[string]any{
         "player": map[string]any{
            "mediaEngine": map[string]string{
               "name":    "", // required
               "version": "", // required
            }, // required
            "playerView": map[string]int{
               "height": 0, // required
               "width":  0, // required
            }, // required
            "sdk": map[string]string{
               "name":    "", // required
               "version": "", // required
            }, // required
         }, // required
      }, // required
   })
   if err != nil {
      return nil, err
   }

   req, err := http.NewRequest(
      http.MethodPost,
      "https://default.prd.api.hbomax.com/playback-orchestrator/any/playback-orchestrator/v1/playbackInfo",
      bytes.NewReader(body),
   )
   if err != nil {
      return nil, err
   }
   req.Header.Set("authorization", "Bearer "+token)
   req.Header.Set("content-type", "application/json")
   req.Header.Set("x-disco-params", disco_params)
   req.Header.Set("x-disco-client", disco_client)
   req.Header.Set("x-device-info", device_info)

   resp, err := doReq(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   var result Playback
   err = json.NewDecoder(resp.Body).Decode(&result)
   if err != nil {
      return nil, err
   }
   if len(result.Errors) > 0 {
      return nil, result.Errors
   }
   return &result, nil
}

// APIError represents a single error object from the Max API
type APIError struct {
   Code    string `json:"code"`    // 2026-08-11
   Status  string `json:"status"`  // 2026-08-11
   Message string `json:"message"` // 2026-08-11
}

// APIErrors represents a collection of API errors and implements the error interface
type APIErrors []APIError

func (e APIErrors) Error() string {
   var b strings.Builder
   for i, err := range e {
      if i > 0 {
         b.WriteString(", ")
      }
      b.WriteString("code: ")
      b.WriteString(err.Code)
      b.WriteString(", status: ")
      b.WriteString(err.Status)
      b.WriteString(", message: ")
      b.WriteString(err.Message)
   }
   return b.String()
}

type Cookie struct {
   Name  string
   Value string
}

func (*Cookie) CachePath() string {
   return "rosso/provider/hboMax/Cookie"
}

func (c *Cookie) String() string {
   return fmt.Sprintf("%v=%v", c.Name, c.Value)
}

func (*Playback) CachePath() string {
   return "rosso/provider/hboMax/Playback"
}

// GetManifest returns the MPD location with the "_fallback" marker removed.
func (p *Playback) GetManifest() string {
   return strings.Replace(p.Fallback.Manifest.Url, "_fallback", "", 1)
}

// SL3000 L1
func (p *Playback) PlayReadyRequest(body []byte) ([]byte, error) {
   req, err := http.NewRequest(http.MethodPost, p.Drm.Schemes.PlayReady.LicenseUrl, bytes.NewReader(body))
   if err != nil {
      return nil, err
   }
   req.Header.Set("content-type", "text/xml")

   resp, err := doReq(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   if resp.StatusCode != http.StatusOK {
      return nil, errors.New(resp.Status)
   }
   return io.ReadAll(resp.Body)
}

func (p *Playback) WidevineRequest(body []byte) ([]byte, error) {
   req, err := http.NewRequest(http.MethodPost, p.Drm.Schemes.Widevine.LicenseUrl, bytes.NewReader(body))
   if err != nil {
      return nil, err
   }
   req.Header.Set("content-type", "application/x-protobuf")

   resp, err := doReq(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   if resp.StatusCode != http.StatusOK {
      return nil, errors.New(resp.Status)
   }
   return io.ReadAll(resp.Body)
}

// client.go KEEP THIS LINE
