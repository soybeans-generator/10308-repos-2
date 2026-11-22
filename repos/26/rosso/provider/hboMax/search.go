package hboMax

import (
   "encoding/json"
   "fmt"
   "log"
   "net/http"
   "net/url"
   "strings"
)

const Markets = "amer apac emea latam"

// types.go
const device_info = "hboMax/hboMax (hboMax/hboMax; hboMax/hboMax; hboMax/hboMax)"

const disco_client = "hboMax:hboMax:hboMax:hboMax"

const disco_params = "hboMax=hboMax"

// doReq handles executing the HTTP request and logging the method/URL
func doReq(req *http.Request) (*http.Response, error) {
   log.Println(req.Method, req.URL)
   return http.DefaultClient.Do(req)
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
   return "rosso/hboMax/Cookie"
}

func (c *Cookie) String() string {
   return fmt.Sprintf("%v=%v", c.Name, c.Value)
}

// Entity represents a single unified node in the Max API response
type Entity struct {
   Attributes struct {
      Name          string
      Alias         string
      ShowType      string
      VideoType     string
      MaterialType  string
      Description   string
      SeasonNumber  int
      EpisodeNumber int
      AirDate       string
   }
   Id            string
   Relationships struct {
      Edit struct {
         Data Resource
      }
      Items struct {
         Data []Resource
      }
      Show struct {
         Data Resource
      }
      Video struct {
         Data Resource
      }
   }
   Type string
}

func SearchRequest(token, query string) ([]*Entity, error) {
   values := url.Values{}
   values.Set("contentFilter[query]", query)
   parsedUrl := &url.URL{
      Path:     "/cms/routes/search/result",
      RawQuery: values.Encode(),
   }
   return entity_request(token, parsedUrl)
}

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

// String implements the fmt.Stringer interface to provide a clean visual
// output for the Entity
func (e *Entity) String() string {
   data := &strings.Builder{}
   if e.Attributes.MaterialType == "EPISODE" {
      fmt.Fprintf(data, "Episode: %d\n", e.Attributes.EpisodeNumber)
   }
   if e.Attributes.ShowType != "" {
      fmt.Fprintf(data, "Show Type: %s\n", e.Attributes.ShowType)
   } else if e.Attributes.VideoType != "" {
      fmt.Fprintf(data, "Video Type: %s\n", e.Attributes.VideoType)
   }
   fmt.Fprintf(data, "Name: %s\n", e.Attributes.Name)
   if e.Type == "video" {
      fmt.Fprintf(data, "Edit ID: %s\n", e.Relationships.Edit.Data.Id)
   } else {
      fmt.Fprintf(data, "ID: %s\n", e.Id)
   }
   return strings.TrimSpace(data.String())
}

type Initiate struct {
   LinkingCode string
   TargetUrl   string
}

func (i *Initiate) String() string {
   var data strings.Builder
   data.WriteString("target URL: ")
   data.WriteString(i.TargetUrl)
   data.WriteString("\nlinking code: ")
   data.WriteString(i.LinkingCode)
   return data.String()
}

type Login struct {
   Token string
}

func (*Login) CachePath() string {
   return "rosso/hboMax/Login"
}

type Playback struct {
   Drm struct {
      Schemes struct {
         PlayReady *Scheme
         Widevine  *Scheme
      }
   }
   Errors   APIErrors `json:"errors"`
   Fallback struct {
      Manifest struct {
         Url string // _fallback.mpd:1080p, .mpd:4K
      }
   }
   Manifest struct {
      Url string // 1080p
   }
}

// Resource represents a relationship pointer in the JSON:API graph
type Resource struct {
   Id   string
   Type string
}

type Scheme struct {
   LicenseUrl string
}
