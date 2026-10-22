// vhx.go
package criterion

import (
   "bytes"
   "encoding/json"
   "errors"
   "fmt"
   "io"
   "net/http"
   "net/url"
)

// FetchFilesHref returns the "files" link of the first item in a collection.
func FetchFilesHref(accessToken, slug string) (string, error) {
   req, err := http.NewRequest(
      "GET",
      fmt.Sprintf("https://api.vhx.com/collections/%v/items?site_id=59054", slug),
      nil,
   )
   if err != nil {
      return "", err
   }
   req.Header.Set("authorization", "Bearer "+accessToken)
   resp, err := do(req)
   if err != nil {
      return "", err
   }
   defer resp.Body.Close()
   var result struct {
      Embedded struct {
         Items []struct {
            Links struct {
               Files struct {
                  Href string // https://api.vhx.tv/videos/3460957/files
               }
            } `json:"_links"`
         }
      } `json:"_embedded"`
   }
   err = json.NewDecoder(resp.Body).Decode(&result)
   if err != nil {
      return "", err
   }
   return result.Embedded.Items[0].Links.Files.Href, nil
}

// File is one playback variant of a video. Source.Href is the MPD.
type File struct {
   DrmAuthorizationToken string `json:"drm_authorization_token"`
   Links                 struct {
      Source struct {
         Href string // MPD
      }
   } `json:"_links"`
   Method string
}

// FetchFiles lists the playback variants behind a files href.
func FetchFiles(accessToken string, files string) ([]File, error) {
   req, err := http.NewRequest("GET", files, nil)
   if err != nil {
      return nil, err
   }
   req.Header.Set("authorization", "Bearer "+accessToken)
   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   if resp.StatusCode != 200 {
      return nil, errors.New(resp.Status)
   }
   var result []File
   err = json.NewDecoder(resp.Body).Decode(&result)
   if err != nil {
      return nil, err
   }
   return result, nil
}

// GetDash picks the DASH variant, which carries the Widevine token.
func GetDash(files []File) (*File, error) {
   for _, fileData := range files {
      if fileData.Method == "dash" {
         return &fileData, nil
      }
   }
   return nil, errors.New("DASH media file not found")
}

// CachePath reports where the file list is cached.
func (*File) CachePath() string {
   return "rosso/criterion/File"
}

// FetchWidevine posts a Widevine challenge to the licence server and returns
// the raw licence response.
func (f *File) FetchWidevine(body []byte) ([]byte, error) {
   req, err := http.NewRequest(
      "POST",
      "https://drm.vhx.com/v2/widevine?"+
         url.Values{"token": {f.DrmAuthorizationToken}}.Encode(),
      bytes.NewReader(body),
   )
   if err != nil {
      return nil, err
   }
   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   return io.ReadAll(resp.Body)
}

// vhx.go
