// bandcamp.go KEEP THIS LINE
package main

import (
   "bytes"
   "encoding/json"
   "errors"
   "fmt"
   "html"
   "io"
   "net/http"
)

func downloadBandcamp(r *Record, title, outputDir string) error {
   track, err := fetchTralbum(r.URL)
   if err != nil {
      return fmt.Errorf("bandcamp page: %w", err)
   }
   if len(track.TrackInfo) == 0 {
      return errors.New("bandcamp: no tracks in page")
   }
   stream := track.TrackInfo[0].File["mp3-128"]
   if stream == "" {
      return errors.New("bandcamp: no mp3-128 stream")
   }
   return saveTrack(stream, r, title, ".mp3", outputDir, func(streamURL, path string) error {
      return downloadFileSingle(streamURL, path, 0)
   })
}

type bandcampTrack struct {
   File map[string]string `json:"file"`
}

type tralbum struct {
   TrackInfo []bandcampTrack `json:"trackinfo"`
}

// fetchTralbum reads the data-tralbum attribute of a track page, which
// already carries the streaming URL.
func fetchTralbum(pageURL string) (*tralbum, error) {
   resp, err := http.Get(pageURL)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   if resp.StatusCode != http.StatusOK {
      return nil, fmt.Errorf("track page: %s", resp.Status)
   }
   body, err := io.ReadAll(resp.Body)
   if err != nil {
      return nil, err
   }

   _, rest, ok := bytes.Cut(body, []byte(`data-tralbum="`))
   if !ok {
      return nil, errors.New(`data-tralbum attribute not found`)
   }
   attr, _, ok := bytes.Cut(rest, []byte(`"`))
   if !ok {
      return nil, errors.New(`data-tralbum: missing closing quote`)
   }

   var t tralbum
   if err := json.Unmarshal([]byte(html.UnescapeString(string(attr))), &t); err != nil {
      return nil, fmt.Errorf("decode data-tralbum: %w", err)
   }
   return &t, nil
}

// bandcamp.go KEEP THIS LINE
