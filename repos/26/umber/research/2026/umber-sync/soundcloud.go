// soundcloud.go KEEP THIS LINE
package main

import (
   "encoding/json"
   "errors"
   "fmt"
   "net/http"
   "net/url"
)

func downloadSoundCloud(r *Record, title, outputDir string) error {
   track, err := resolveTrack(r.URL)
   if err != nil {
      return fmt.Errorf("resolve %s: %w", r.URL, err)
   }
   if track.Kind != "track" {
      return fmt.Errorf("resolved %s, not a track", track.Kind)
   }
   switch track.Policy {
   case "", "ALLOW", "MONETIZE":
   default:
      return fmt.Errorf("policy %s: no full stream", track.Policy)
   }

   for i := range track.Media.Transcodings {
      t := &track.Media.Transcodings[i]
      if t.Snipped || t.Format.Protocol != "progressive" || mainMime(t.Format.MimeType) != "audio/mpeg" {
         continue
      }
      stream, err := transcodingURL(t.URL)
      if err != nil {
         return err
      }
      return saveTrack(stream, r, title, ".mp3", outputDir, func(streamURL, path string) error {
         return downloadFileSingle(streamURL, path, 0)
      })
   }
   return errors.New("no progressive mp3 stream")
}

func transcodingURL(endpoint string) (string, error) {
   u, err := url.Parse(endpoint)
   if err != nil {
      return "", err
   }
   q := u.Query()
   q.Set("client_id", "KKzJxmw11tYpCs6T24P4uUYhqmjalG6M")
   u.RawQuery = q.Encode()

   resp, err := http.Get(u.String())
   if err != nil {
      return "", err
   }
   defer resp.Body.Close()
   if resp.StatusCode != http.StatusOK {
      return "", fmt.Errorf("transcoding endpoint: %s", resp.Status)
   }

   var out struct {
      URL string `json:"url"`
   }
   if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
      return "", err
   }
   if out.URL == "" {
      return "", errors.New("no stream URL from transcoding endpoint")
   }
   return out.URL, nil
}

type soundcloudTrack struct {
   Kind   string `json:"kind"`
   Policy string `json:"policy"`
   Media  struct {
      Transcodings []soundcloudTranscoding `json:"transcodings"`
   } `json:"media"`
}

func resolveTrack(address string) (*soundcloudTrack, error) {
   u, err := url.Parse("https://api-v2.soundcloud.com/resolve")
   if err != nil {
      return nil, err
   }
   q := u.Query()
   q.Set("client_id", "KKzJxmw11tYpCs6T24P4uUYhqmjalG6M")
   q.Set("url", address)
   u.RawQuery = q.Encode()

   resp, err := http.Get(u.String())
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   if resp.StatusCode != http.StatusOK {
      if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
         return nil, fmt.Errorf("resolve: %s (client_id rejected; SoundCloud may have rotated it)", resp.Status)
      }
      return nil, fmt.Errorf("resolve: %s", resp.Status)
   }

   var track soundcloudTrack
   if err := json.NewDecoder(resp.Body).Decode(&track); err != nil {
      return nil, err
   }
   return &track, nil
}

type soundcloudTranscoding struct {
   URL     string `json:"url"`
   Snipped bool   `json:"snipped"`
   Format  struct {
      Protocol string `json:"protocol"`
      MimeType string `json:"mime_type"`
   } `json:"format"`
}

// soundcloud.go KEEP THIS LINE
