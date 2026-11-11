// Package tubidrm makes the two HTTP calls needed for Tubi Widevine playback:
// the request that fetches the license-request values, and the license request
// itself, whose body the caller supplies.
package tubidrm

import (
   "encoding/json"
   "fmt"
   "io"
   "net/http"
   "net/url"
   "time"
)

const (
   ContentEndpoint = "https://content-cdn.production-public.tubi.io/api/v3/content"

   ResourceWidevine  = "hlsv6_widevine_nonclearlead"
   ResourcePlayReady = "hlsv6_playready_psshv0"
   ResourceFairPlay  = "hlsv6_fairplay"

   defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:158.0) Gecko/20100101 Firefox/158.0"
   defaultOrigin    = "https://tubitv.com"
   defaultReferer   = "https://tubitv.com/"
)

// Values is everything the license request is built from.
type Values struct {
   VideoResourceType string
   URL               string // license endpoint, already carries external_id and drm_token
   Platform          string
   Type              string
   ExternalID        string
   DRMToken          string
   HDCPVersion       string
   AuthHeaderKey     string
   AuthHeaderValue   string
}

// FetchValues performs the request that yields the license-request values.
func FetchValues(hc *http.Client, r ValuesRequest) (Values, error) {
   if hc == nil {
      hc = &http.Client{Timeout: 30 * time.Second}
   }
   if r.ContentID == "" || r.DeviceID == "" {
      return Values{}, fmt.Errorf("tubidrm: ContentID and DeviceID are required")
   }

   req, err := http.NewRequest(http.MethodGet, r.contentURL(), nil)
   if err != nil {
      return Values{}, err
   }
   h := req.Header
   h.Set("Accept", "*/*")
   h.Set("Accept-Language", "en-US")
   h.Set("User-Agent", r.userAgent())
   h.Set("Origin", defaultOrigin)
   h.Set("Referer", defaultReferer)
   h.Set("Accept-Version", "~5.0.0")
   h.Set("X-Capability", `{"content_types":["se"]}`)
   if r.AccessToken != "" {
      h.Set("Authorization", "Bearer "+r.AccessToken)
      h.Set("Cookie", "at="+r.AccessToken)
   }

   resp, err := hc.Do(req)
   if err != nil {
      return Values{}, fmt.Errorf("tubidrm: values request: %w", err)
   }
   defer resp.Body.Close()

   body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
   if err != nil {
      return Values{}, fmt.Errorf("tubidrm: reading values response: %w", err)
   }
   if resp.StatusCode != http.StatusOK {
      return Values{}, &StatusError{
         Op:     "values request",
         Status: resp.StatusCode,
         Body:   body,
      }
   }

   v, err := parseValues(body, r.resourceType())
   if err != nil {
      return Values{}, err
   }
   return v, nil
}

func parseValues(body []byte, want string) (Values, error) {
   var cr contentResponse
   if err := json.Unmarshal(body, &cr); err != nil {
      return Values{}, fmt.Errorf("tubidrm: decoding values response: %w", err)
   }

   var fallback *Values
   for _, vr := range cr.VideoResources {
      ls := vr.LicenseServer
      if ls == nil || ls.URL == "" {
         continue
      }
      v := Values{
         VideoResourceType: vr.Type,
         URL:               ls.URL,
         HDCPVersion:       ls.HDCPVersion,
         AuthHeaderKey:     ls.AuthHeaderKey,
         AuthHeaderValue:   ls.AuthHeaderValue,
      }
      if u, err := url.Parse(ls.URL); err == nil {
         q := u.Query()
         v.Platform = q.Get("platform")
         v.Type = q.Get("type")
         v.ExternalID = q.Get("external_id")
         v.DRMToken = q.Get("drm_token")
      }
      if vr.Type == want {
         return v, nil
      }
      if fallback == nil {
         fallback = &v
      }
   }
   if fallback != nil {
      return *fallback, nil
   }
   return Values{}, fmt.Errorf("tubidrm: no license_server for resource %q in values response", want)
}

// Apply installs the per-asset auth header pair when a value is present.
func (v Values) Apply(h http.Header) {
   if v.AuthHeaderKey != "" && v.AuthHeaderValue != "" {
      h.Set(v.AuthHeaderKey, v.AuthHeaderValue)
   }
}

// ValuesRequest is the input to the values request.
type ValuesRequest struct {
   ContentID    string
   DeviceID     string
   AccessToken  string // "at" cookie / bearer token
   ResourceType string // defaults to ResourceWidevine
   UserAgent    string
}

func (r ValuesRequest) contentURL() string {
   q := url.Values{}
   q.Set("app_id", "tubitv")
   q.Set("platform", "web")
   q.Set("content_id", r.ContentID)
   q.Set("device_id", r.DeviceID)
   q.Set("include_channels", "true")
   q.Set("video_resource_tag", "with_fallback")
   q.Set("limit_resolutions[]", "h264_1080p")
   q.Add("video_resources[]", r.resourceType())
   return ContentEndpoint + "?" + q.Encode()
}

func (r ValuesRequest) resourceType() string {
   if r.ResourceType != "" {
      return r.ResourceType
   }
   return ResourceWidevine
}

func (r ValuesRequest) userAgent() string {
   if r.UserAgent != "" {
      return r.UserAgent
   }
   return defaultUserAgent
}

type contentResponse struct {
   VideoResources []struct {
      Type          string `json:"type"`
      LicenseServer *struct {
         URL             string `json:"url"`
         HDCPVersion     string `json:"hdcp_version"`
         AuthHeaderKey   string `json:"auth_header_key"`
         AuthHeaderValue string `json:"auth_header_value"`
      } `json:"license_server"`
   } `json:"video_resources"`
}
