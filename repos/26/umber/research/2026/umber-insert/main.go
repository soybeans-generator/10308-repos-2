// main.go KEEP THIS LINE
package main

import (
   "bytes"
   "cmp"
   "encoding/json"
   "errors"
   "flag"
   "fmt"
   "log"
   "net/url"
   "os"
   "path/filepath"
   "slices"
   "time"
)

// addYouTubeURL adds a watch URL. A rejected visitor ID is dropped from the
// config so the next run starts over with a fresh one.
func addYouTubeURL(rawURL, songsPath, cfgPath string, cfg *config) error {
   parsed, err := url.Parse(rawURL)
   if err != nil {
      return fmt.Errorf("parse video URL: %w", err)
   }
   videoID := parsed.Query().Get("v")
   if videoID == "" {
      return errors.New("video URL has no 'v' query parameter")
   }

   if err := addYouTube(videoID, songsPath, cfg.VisitorID); !errors.Is(err, errVisitorExpired) {
      return err
   } else {
      log.Printf("visitor ID rejected (%v); discarding it", err)
   }
   cfg.VisitorID = ""
   return saveConfig(cfgPath, cfg)
}

func hasAddress(songs []*song, address string) bool {
   for _, s := range songs {
      if s.address() == address {
         return true
      }
   }
   return false
}

func main() {
   log.SetFlags(log.Ltime)

   bandcampAddr := flag.String("b", "", "Bandcamp track address")
   fileName := flag.String("n", "", "songs JSON file (required on the first run)")
   soundcloudAddr := flag.String("s", "", "SoundCloud track address")
   videoURL := flag.String("y", "", "YouTube video URL")
   flag.Parse()

   dir, err := os.UserConfigDir()
   if err != nil {
      log.Fatalf("locate config dir: %v", err)
   }
   cfgPath := filepath.Join(dir, "umber", "umber.json")
   cfg, err := loadConfig(cfgPath)
   if err != nil {
      log.Fatal(err)
   }

   // Only the YouTube path needs a visitor ID, so fetch it on demand and keep
   // it for later runs.
   if cfg.VisitorID == "" && *videoURL != "" {
      if cfg.VisitorID, err = fetchVisitorID(); err != nil {
         log.Fatalf("fetch visitor ID: %v", err)
      }
      log.Print("visitor ID fetched")
      if err := saveConfig(cfgPath, cfg); err != nil {
         log.Fatal(err)
      }
   }

   if *fileName != "" {
      cfg.InputFile = *fileName
      if err := saveConfig(cfgPath, cfg); err != nil {
         log.Fatal(err)
      }
   }
   if cfg.InputFile == "" {
      log.Fatal("-n is required on the first run")
   }

   var runErr error
   switch {
   case *bandcampAddr != "":
      runErr = addBandcamp(*bandcampAddr, cfg.InputFile)
   case *soundcloudAddr != "":
      runErr = addSoundcloud(*soundcloudAddr, cfg.InputFile)
   case *videoURL != "":
      runErr = addYouTubeURL(*videoURL, cfg.InputFile, cfgPath, cfg)
   default:
      flag.Usage()
   }
   if runErr != nil {
      log.Fatal(runErr)
   }
}

func saveConfig(path string, cfg *config) error {
   if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
      return fmt.Errorf("create config dir: %w", err)
   }
   raw, err := json.MarshalIndent(cfg, "", "  ")
   if err != nil {
      return err
   }
   return os.WriteFile(path, raw, 0o644)
}

func saveSongs(path string, songs []*song) error {
   var buf bytes.Buffer
   enc := json.NewEncoder(&buf)
   enc.SetEscapeHTML(false)
   enc.SetIndent("", " ")
   if err := enc.Encode(songs); err != nil {
      return err
   }
   log.Printf("writing %s", path)
   return os.WriteFile(path, buf.Bytes(), 0o644)
}

func sortNewestFirst(songs []*song) {
   slices.SortFunc(songs, func(a, b *song) int { return cmp.Compare(b.addedAt(), a.addedAt()) })
}

// config lives at <user config dir>/umber/umber.json.
type config struct {
   VisitorID string `json:"visitor_id"`
   InputFile string `json:"input_file"`
}

func loadConfig(path string) (*config, error) {
   raw, err := os.ReadFile(path)
   switch {
   case errors.Is(err, os.ErrNotExist):
      return &config{}, nil
   case err != nil:
      return nil, fmt.Errorf("read config: %w", err)
   }
   var cfg config
   if err := json.Unmarshal(raw, &cfg); err != nil {
      return nil, fmt.Errorf("parse config: %w", err)
   }
   return &cfg, nil
}

// song is one on-disk record:
//
//   {"A": [<unix time added>, <release year>],
//    "B": [<artist>, <title>, <address>, <image?>]}
type song struct {
   A [2]int64 `json:"A"`
   B []string `json:"B"`
}

func loadSongs(path string) ([]*song, error) {
   raw, err := os.ReadFile(path)
   if err != nil {
      return nil, err
   }
   var songs []*song
   if err := json.Unmarshal(raw, &songs); err != nil {
      return nil, fmt.Errorf("parse %s: %w", path, err)
   }
   return songs, nil
}

// newSong leaves the image slot off entirely when there is no artwork.
func newSong(f songFields) *song {
   b := []string{f.artist, f.title, f.address}
   if f.image != "" {
      b = append(b, f.image)
   }
   return &song{A: [2]int64{time.Now().Unix(), int64(f.year)}, B: b}
}
func (s *song) addedAt() int64 { return s.A[0] }

func (s *song) address() string { return s.B[2] }

// songFields is the provider-supplied part of a record; addedAt is always now.
type songFields struct {
   artist, title, address, image string
   year                          int
}

// main.go KEEP THIS LINE
