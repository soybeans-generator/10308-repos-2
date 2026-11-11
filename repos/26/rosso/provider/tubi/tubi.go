package tubi

import (
   "bytes"
   "encoding/json"
   "errors"
   "io"
   "log"
   "net/http"
   "net/url"
   "strconv"
)

func AcquireLicense(server *LicenseServer, body []byte) ([]byte, error) {
   req, err := http.NewRequest("POST", server.Url, bytes.NewReader(body))
   if err != nil {
      return nil, err
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

func do(req *http.Request) (*http.Response, error) {
   log.Println(req.Method, req.URL)
   return http.DefaultClient.Do(req)
}

type ContentResponse struct {
   VideoResources []VideoResource `json:"video_resources"`
}

func GetContent(contentId int) (*ContentResponse, error) {
   target := &url.URL{
      Scheme: "https",
      Host:   "uapi.adrise.tv",
      Path:   "/cms/content",
   }

   query := url.Values{}
   query.Set("content_id", strconv.Itoa(contentId))
   query.Set("deviceId", "deviceId")
   query.Set("platform", "web")
   query.Add("video_resources[]", "dash_playready_psshv0")
   query.Add("limit_resolutions[]", "h265_1080p")
   target.RawQuery = query.Encode()

   req, err := http.NewRequest("GET", target.String(), nil)
   if err != nil {
      return nil, err
   }
   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

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
   Manifest      Manifest      `json:"manifest"`
   LicenseServer LicenseServer `json:"license_server"`
}
