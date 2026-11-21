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
   "time"
)

func addBandcamp(address, songsPath string) error {
   songs, err := loadSongs(songsPath)
   if err != nil {
      return err
   }
   if hasAddress(songs, address) {
      return fmt.Errorf("%s is already listed in %s", address, songsPath)
   }

   info, err := fetchTralbum(address)
   if err != nil {
      return err
   }

   // Standalone tracks carry no album_release_date; fall back to the track's
   // own release date. Both look like "12 Jun 2026 00:00:00 GMT".
   date := info.AlbumReleaseDate
   if date == "" {
      date = info.Current.ReleaseDate
   }
   released, err := time.Parse("02 Jan 2006 15:04:05 GMT", date)
   if err != nil {
      return fmt.Errorf("%s: release date %q: %w", address, date, err)
   }

   songs = append(songs, newSong(songFields{
      artist:  info.Artist,
      title:   info.Current.Title,
      address: address,
      image:   fmt.Sprintf("https://f4.bcbits.com/img/a%d_5", info.ArtID), // 700x700
      year:    released.Year(),
   }))
   sortNewestFirst(songs)
   return saveSongs(songsPath, songs)
}

type tralbum struct {
   Artist           string `json:"artist"`
   ArtID            int    `json:"art_id"`
   AlbumReleaseDate string `json:"album_release_date"`
   Current          struct {
      Title       string `json:"title"`
      ReleaseDate string `json:"release_date"`
   } `json:"current"`
}

func fetchTralbum(address string) (*tralbum, error) {
   resp, err := http.Get(address)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   if resp.StatusCode != http.StatusOK {
      return nil, fmt.Errorf("tralbum page: %s", resp.Status)
   }

   page, err := io.ReadAll(resp.Body)
   if err != nil {
      return nil, err
   }

   // The blob is an HTML-entity-encoded JSON attribute on a <script> tag. The
   // quote right after the name keeps data-tralbum-collect-info from matching.
   _, rest, ok := bytes.Cut(page, []byte(`data-tralbum="`))
   if !ok {
      return nil, errors.New(`attribute "data-tralbum" is missing`)
   }
   raw, _, ok := bytes.Cut(rest, []byte(`"`))
   if !ok {
      return nil, errors.New("data-tralbum value is not terminated")
   }

   var info tralbum
   if err := json.Unmarshal([]byte(html.UnescapeString(string(raw))), &info); err != nil {
      return nil, fmt.Errorf("decode data-tralbum: %w", err)
   }
   return &info, nil
}

// bandcamp.go KEEP THIS LINE
