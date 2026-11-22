// client.go
package disney

import (
   "bytes"
   "encoding/json"
   "errors"
   "io"
   "log"
   "net/http"
   "net/url"
   "path"
   "strings"
)

// https://disneyplus.com/browse/entity-7df81cf5-6be5-4e05-9ff6-da33baf0b94d
// https://disneyplus.com/cs-cz/browse/entity-7df81cf5-6be5-4e05-9ff6-da33baf0b94d
// https://disneyplus.com/play/7df81cf5-6be5-4e05-9ff6-da33baf0b94d
func GetEntityId(rawUrl string) (string, error) {
   parsed, err := url.Parse(rawUrl)
   if err != nil {
      return "", err
   }
   base := path.Base(parsed.Path)
   if !strings.HasPrefix(base, "entity-") {
      return "", errors.New("entity value missing from URL")
   }
   return base, nil
}

func do(req *http.Request) (*http.Response, error) {
   log.Println(req.Method, req.URL)
   return http.DefaultClient.Do(req)
}

type Error struct {
   Code        string // 2026-04-05
   Description string // 2026-04-05
}

func (e *Error) Error() string {
   var data strings.Builder
   data.WriteString("code: ")
   data.WriteString(e.Code)
   data.WriteString("\ndescription: ")
   data.WriteString(e.Description)
   return data.String()
}

type Page struct {
   Actions []struct {
      InternalTitle string // movie
   }
   Containers []struct {
      Seasons []struct { // series
         Visuals struct {
            Name string
         }
         Id string
      }
   }
   Visuals struct {
      Restriction struct {
         Message string // 2026-08-16
      }
   }
}

func (p *Page) String() string {
   var data strings.Builder
   if len(p.Containers[0].Seasons) >= 1 {
      var line bool
      for _, seasonItem := range p.Containers[0].Seasons {
         if line {
            data.WriteString("\n\n")
         } else {
            line = true
         }
         data.WriteString("name: ")
         data.WriteString(seasonItem.Visuals.Name)
         data.WriteString("\nid: ")
         data.WriteString(seasonItem.Id)
      }
   } else {
      data.WriteString(p.Actions[0].InternalTitle)
   }
   return data.String()
}

type Season struct {
   Items []struct {
      Actions []struct {
         InternalTitle string
      }
   }
}

func (s Season) String() string {
   var (
      data strings.Builder
      line bool
   )
   for _, item := range s.Items {
      for _, action := range item.Actions {
         if line {
            data.WriteByte('\n')
         } else {
            line = true
         }
         data.WriteString(action.InternalTitle)
      }
   }
   return data.String()
}

type Token struct {
   AccessTokenType string
   AccessToken     string
   RefreshToken    string
}

func (*Token) CachePath() string {
   return "rosso/disney/Token"
}

// request: Account
func (t *Token) FetchPage(entity string) (*Page, error) {
   if err := t.assert("Account"); err != nil {
      return nil, err
   }
   req, err := http.NewRequest(
      "GET",
      "https://disney.api.edge.bamgrid.com/explore/v1.12/page/"+entity+"?limit=0",
      nil,
   )
   if err != nil {
      return nil, err
   }
   req.Header.Set("authorization", "Bearer "+t.AccessToken)
   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   var result struct {
      Data struct {
         Errors []Error // 2026-04-11
         Page   Page
      }
      Errors []Error // 2026-05-03
   }
   err = json.NewDecoder(resp.Body).Decode(&result)
   if err != nil {
      return nil, err
   }
   if len(result.Errors) >= 1 {
      return nil, &result.Errors[0]
   }
   if len(result.Data.Errors) >= 1 {
      return nil, &result.Data.Errors[0]
   }
   if restriction := result.Data.Page.Visuals.Restriction.Message; restriction != "" {
      return nil, errors.New(restriction)
   }
   return &result.Data.Page, nil
}

// SL2000 max: 720p
// SL3000 max: 2160p
// request: Account
func (t *Token) FetchPlayReady(body []byte) ([]byte, error) {
   if err := t.assert("Account"); err != nil {
      return nil, err
   }
   req, err := http.NewRequest(
      "POST",
      "https://disney.playback.edge.bamgrid.com/playready/v1/obtain-license.asmx",
      bytes.NewReader(body),
   )
   if err != nil {
      return nil, err
   }
   req.Header.Set("authorization", t.AccessToken)
   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   if resp.StatusCode != 200 {
      return nil, errors.New(resp.Status)
   }
   return io.ReadAll(resp.Body)
}

// request: Account
func (t *Token) FetchSeason(id string) (*Season, error) {
   if err := t.assert("Account"); err != nil {
      return nil, err
   }
   req, err := http.NewRequest(
      "GET",
      "https://disney.api.edge.bamgrid.com/explore/v1.12/season/"+id+"?limit=99",
      nil,
   )
   if err != nil {
      return nil, err
   }
   req.Header.Set("authorization", "Bearer "+t.AccessToken)
   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   var result struct {
      Data struct {
         Season Season
      }
   }
   err = json.NewDecoder(resp.Body).Decode(&result)
   if err != nil {
      return nil, err
   }
   return &result.Data.Season, nil
}

// request: Account
func (t *Token) FetchStream(mediaId string) (*url.URL, error) {
   if err := t.assert("Account"); err != nil {
      return nil, err
   }
   playback_id, err := json.Marshal(map[string]string{
      "mediaId": mediaId,
   })
   if err != nil {
      return nil, err
   }
   body, err := json.Marshal(map[string]any{
      "playback": map[string]any{
         "attributes": map[string]any{
            "assetInsertionStrategy": "SGAI",
            "codecs": map[string]any{
               "supportsMultiCodecMaster": true, // 4K
               "video": []string{
                  "h.264",
                  "h.265",
               },
            },
            "videoRanges": []string{"HDR10"},
         },
      },
      "playbackId": playback_id,
   })
   if err != nil {
      return nil, err
   }
   req, err := http.NewRequest(
      "POST",
      "https://disney.playback.edge.bamgrid.com/v7/playback/ctr-regular",
      bytes.NewReader(body),
   )
   if err != nil {
      return nil, err
   }
   req.Header.Set("authorization", "Bearer "+t.AccessToken)
   req.Header.Set("content-type", "application/json")
   req.Header.Set("x-application-version", "")
   req.Header.Set("x-bamsdk-client-id", "")
   req.Header.Set("x-bamsdk-platform", "")
   req.Header.Set("x-bamsdk-version", "")
   req.Header.Set("x-dss-feature-filtering", "true")
   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   var result struct {
      Stream struct {
         Sources []struct {
            Complete struct {
               Url string
            }
         }
      }
   }
   err = json.NewDecoder(resp.Body).Decode(&result)
   if err != nil {
      return nil, err
   }
   return url.Parse(result.Stream.Sources[0].Complete.Url)
}

// L3 max: 720p
// request: Account
func (t *Token) FetchWidevine(body []byte) ([]byte, error) {
   if err := t.assert("Account"); err != nil {
      return nil, err
   }
   req, err := http.NewRequest(
      "POST",
      "https://disney.playback.edge.bamgrid.com/widevine/v1/obtain-license",
      bytes.NewReader(body),
   )
   if err != nil {
      return nil, err
   }
   req.Header.Set("authorization", t.AccessToken)
   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   return io.ReadAll(resp.Body)
}

func (t *Token) String() string {
   var data strings.Builder
   data.WriteString("type: ")
   data.WriteString(t.AccessTokenType)
   data.WriteString("\naccess token: ")
   data.WriteString(t.AccessToken)
   if t.RefreshToken != "" {
      data.WriteString("\nrefresh token: ")
      data.WriteString(t.RefreshToken)
   }
   return data.String()
}

func (t *Token) assert(expected string) error {
   if t.AccessTokenType != expected {
      return errors.New("expected token type " + expected)
   }
   return nil
}
