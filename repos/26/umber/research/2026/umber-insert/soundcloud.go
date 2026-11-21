// soundcloud.go KEEP THIS LINE
package main

import (
   "encoding/json"
   "errors"
   "fmt"
   "net/http"
   "net/url"
   "strings"
   "time"
)

func addSoundcloud(address, songsPath string) error {
   songs, err := loadSongs(songsPath)
   if err != nil {
      return err
   }
   if hasAddress(songs, address) {
      return fmt.Errorf("%s is already listed in %s", address, songsPath)
   }

   item, err := resolveTrack(address)
   if err != nil {
      return err
   }
   if item.Kind != "track" {
      return fmt.Errorf("%s resolved to a %q, not a track", address, item.Kind)
   }
   if item.Title == "" {
      return fmt.Errorf("%s: resolve answer carries no title", address)
   }
   if err := checkStream(item); err != nil {
      return fmt.Errorf("%s: %w", address, err)
   }

   art := item.ArtworkURL
   if art == "" {
      art = item.User.AvatarURL
   }

   songs = append(songs, newSong(songFields{
      artist:  item.User.Username,
      title:   item.Title,
      address: address,
      image:   strings.Replace(art, "-large", "-t500x500", 1),
      year:    item.DisplayDate.Year(),
   }))
   sortNewestFirst(songs)
   return saveSongs(songsPath, songs)
}

// checkStream reports whether the resolve answer already shows the plain
// progressive mp3 the downloader fetches: no DRM, a full stream allowed, and an
// unsnipped progressive mp3 transcoding.
func checkStream(item *scTrack) error {
   for _, t := range item.Media.Transcodings {
      // Major-label tracks are served only over cbc-/ctr-encrypted HLS; the
      // plain transcodings listed beside them answer 404.
      if strings.Contains(t.Format.Protocol, "encrypted") {
         return errors.New("DRM-only: every stream is encrypted")
      }
   }

   switch item.Policy {
   case "", "ALLOW", "MONETIZE":
   default:
      // SNIPPET is a Go+ preview, BLOCK is geo-blocked or taken down.
      return fmt.Errorf("policy %q does not allow a full stream", item.Policy)
   }

   for _, t := range item.Media.Transcodings {
      if t.Snipped {
         continue
      }
      mime := t.Format.MimeType
      if i := strings.IndexByte(mime, ';'); i >= 0 {
         mime = mime[:i]
      }
      if strings.TrimSpace(mime) == "audio/mpeg" && t.Format.Protocol == "progressive" {
         return nil
      }
   }
   return errors.New("no progressive mp3 transcoding")
}

type scTrack struct {
   ArtworkURL  string    `json:"artwork_url"`
   DisplayDate time.Time `json:"display_date"`
   Kind        string
   Policy      string
   Title       string
   User        struct {
      AvatarURL string `json:"avatar_url"`
      Username  string
   }
   Media struct {
      Transcodings []scTranscoding `json:"transcodings"`
   }
}

func resolveTrack(address string) (*scTrack, error) {
   req, err := http.NewRequest(http.MethodGet, "https://api-v2.soundcloud.com/resolve", nil)
   if err != nil {
      return nil, err
   }
   // SoundCloud's public web client, the same value the downloader sends.
   req.URL.RawQuery = url.Values{
      "client_id": {"KKzJxmw11tYpCs6T24P4uUYhqmjalG6M"},
      "url":       {address},
   }.Encode()

   resp, err := http.DefaultClient.Do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   switch resp.StatusCode {
   case http.StatusOK:
   case http.StatusUnauthorized, http.StatusForbidden:
      return nil, fmt.Errorf("resolve: %s (client_id rejected; SoundCloud probably rotated it)", resp.Status)
   default:
      return nil, fmt.Errorf("resolve: %s", resp.Status)
   }

   var item scTrack
   if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
      return nil, fmt.Errorf("decode resolve answer: %w", err)
   }
   return &item, nil
}

type scTranscoding struct {
   Snipped bool `json:"snipped"`
   Format  struct {
      Protocol string `json:"protocol"`
      MimeType string `json:"mime_type"`
   }
}

// soundcloud.go KEEP THIS LINE
