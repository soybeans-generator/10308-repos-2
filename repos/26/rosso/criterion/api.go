// api.go
package criterion

import (
   "bytes"
   "encoding/json"
   "fmt"
   "io"
   "net/http"
   "net/url"
   "strings"
)

// APIBase is the Next.js app that serves the catalogue and playback endpoints.
const APIBase = "https://www.criterionchannel.com"

// Media is GET /api/media/{media_id}. Its Sources are unsigned and not
// playable; FetchPlayback returns the signed ones.
type Media struct {
   MediaID     string `json:"mediaid"`
   CriterionID string `json:"criterion_id"`
   Title       string `json:"title"`
   Duration    int    `json:"duration"`
   Paywall     string `json:"paywall"`
   DRM         bool   `json:"drm"`
   ContentType string `json:"contentType"`
   Deeplink    string `json:"deeplink"`
}

// Playback is GET /api/playback/{media_id}. The signed tokens in it are what
// make manifest.mpd playable, so this is the request that must follow Media.
type Playback struct {
   Playlist []struct {
      MediaID  string   `json:"mediaid"`
      Title    string   `json:"title"`
      Duration int      `json:"duration"`
      DRM      bool     `json:"drm"`
      Sources  []Source `json:"sources"`
   } `json:"playlist"`
}

// GetDash picks the DASH variant, which carries the Widevine licence URL.
func (p *Playback) GetDash() (*Source, error) {
   for _, item := range p.Playlist {
      for index := range item.Sources {
         if item.Sources[index].Type == "application/dash+xml" {
            return &item.Sources[index], nil
         }
      }
   }
   return nil, fmt.Errorf("DASH media file not found")
}

// Session authenticates the criterionchannel.com API. Token is the Auth0 access
// token from the device grant, sent as a bearer. Cookie is the web fallback:
// __session plus criterion_dz_logged_in=1. Whichever is set gets sent; Token
// wins when both are.
type Session struct {
   Token    string `json:"access_token"`
   LoggedIn string `json:"criterion_dz_logged_in"`
   Cookie   string `json:"__session"`
}

// CachePath reports where the session is cached.
func (*Session) CachePath() string {
   return "rosso/criterion/Session"
}

// FetchMedia returns the catalogue record for one media id.
func (s *Session) FetchMedia(mediaID string) (*Media, error) {
   var media Media
   if err := s.get("/api/media/"+url.PathEscape(mediaID), &media); err != nil {
      return nil, err
   }
   return &media, nil
}

// FetchPlayback returns the signed playback entries for one media id.
func (s *Session) FetchPlayback(mediaID string) (*Playback, error) {
   var playback Playback
   if err := s.get("/api/playback/"+url.PathEscape(mediaID), &playback); err != nil {
      return nil, err
   }
   return &playback, nil
}

// authorize attaches whichever credential Session carries.
func (s *Session) authorize(req *http.Request) {
   if s.Token != "" {
      req.Header.Set("authorization", "Bearer "+s.Token)
      return
   }
   if s.Cookie != "" {
      loggedIn := s.LoggedIn
      if loggedIn == "" {
         loggedIn = "1"
      }
      req.AddCookie(&http.Cookie{Name: "criterion_dz_logged_in", Value: loggedIn})
      req.AddCookie(&http.Cookie{Name: "__session", Value: s.Cookie})
   }
}

// get fetches route and decodes JSON into value.
func (s *Session) get(route string, value any) error {
   req, err := http.NewRequest("GET", APIBase+route, nil)
   if err != nil {
      return err
   }
   req.Header.Set("accept", "application/json")
   s.authorize(req)
   resp, err := do(req)
   if err != nil {
      return err
   }
   defer resp.Body.Close()
   if resp.StatusCode != 200 {
      body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
      return fmt.Errorf("%v: %v", resp.Status, strings.TrimSpace(string(body)))
   }
   return json.NewDecoder(resp.Body).Decode(value)
}

// Source is one playback variant from /api/playback. File is the signed
// manifest URL; Drm holds the licence endpoints for that same variant.
type Source struct {
   File string `json:"file"`
   Type string `json:"type"`
   Drm  struct {
      Widevine struct {
         URL string `json:"url"`
      } `json:"widevine"`
      PlayReady struct {
         URL string `json:"url"`
      } `json:"playready"`
   } `json:"drm"`
}

// CachePath reports where the picked source is cached.
func (*Source) CachePath() string {
   return "rosso/criterion/Source"
}

// FetchWidevine posts a Widevine challenge to the licence URL from playback and
// returns the raw licence response. The request is unchanged from the old host;
// only the URL now comes from the playback JSON, so headers can be added here
// once the licence exchange is captured.
func (s *Source) FetchWidevine(body []byte) ([]byte, error) {
   if s.Drm.Widevine.URL == "" {
      return nil, fmt.Errorf("no widevine URL for %v", s.Type)
   }
   req, err := http.NewRequest("POST", s.Drm.Widevine.URL, bytes.NewReader(body))
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

// api.go
