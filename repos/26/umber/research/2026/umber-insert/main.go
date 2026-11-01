// main.go marker preserve
package main

import (
   "bytes"
   "encoding/json"
   "errors"
   "flag"
   "log"
   "net/url"
   "os"
   "path/filepath"
)

// Field positions inside the positional record. A is [timestamp, year];
// B is [artist, title, address, image?]. The image slot is optional, so
// B is three elements long for tracks without artwork.
const (
   posTime    = 0 // A[0]: unix timestamp
   posYear    = 1 // A[1]: release year
   posArtist  = 0 // B[0]
   posTitle   = 1 // B[1]
   posAddress = 2 // B[2]
   posImage   = 3 // B[3]: optional
)

// contains_song reports whether a song with the given address already exists.
func contains_song(songs []*song, address string) bool {
   for _, s := range songs {
      if s.address() == address {
         return true
      }
   }
   return false
}

func main() {
   log.SetFlags(log.Ltime)

   address := flag.String("b", "", "Bandcamp address")
   name := flag.String("n", "", "input JSON file path (required on first run)")
   soundcloud_url := flag.String("s", "", "SoundCloud address")
   video_url := flag.String("y", "", "YouTube video URL")

   flag.Parse()

   // ── Config ───────────────────────────────────────────────────────

   configDir, err := os.UserConfigDir()
   if err != nil {
      log.Fatalf("cannot determine config dir: %v", err)
   }
   configPath := filepath.Join(configDir, "umber", "umber.json")

   var cfg config
   data, err := os.ReadFile(configPath)
   switch {
   case err == nil:
      if err := json.Unmarshal(data, &cfg); err != nil {
         log.Fatalf("cannot parse config: %v", err)
      }
   case errors.Is(err, os.ErrNotExist):
      // first run, no config yet
   default:
      log.Fatalf("cannot read config: %v", err)
   }

   // ── Visitor ID ──────────────────────────────────────────────────

   if cfg.VisitorID == "" && *video_url != "" {
      visitorId, err := fetchVisitorID()
      if err != nil {
         log.Fatalf("cannot fetch visitor ID: %v", err)
      }
      cfg.VisitorID = visitorId
      log.Printf("visitor ID fetched")
      saveConfig(configPath, &cfg)
   }

   // ── Input file ──────────────────────────────────────────────────

   var inputPath string
   if *name != "" {
      inputPath = *name
      cfg.InputFile = inputPath
      saveConfig(configPath, &cfg)
   } else if cfg.InputFile != "" {
      inputPath = cfg.InputFile
   } else {
      log.Fatal("-n is required on first run")
   }

   // ── Dispatch ────────────────────────────────────────────────────

   switch {
   case *address != "":
      if err := do_bandcamp(*address, inputPath); err != nil {
         log.Fatal(err)
      }
   case *soundcloud_url != "":
      if err := do_soundcloud(*soundcloud_url, inputPath); err != nil {
         log.Fatal(err)
      }
   case *video_url != "":
      u, err := url.Parse(*video_url)
      if err != nil {
         log.Fatal("Invalid URL:", err)
      }

      video_id := u.Query().Get("v")
      if video_id == "" {
         log.Fatal("Could not extract 'v' parameter from URL")
      }

      err = do_video_id(video_id, inputPath, cfg.VisitorID)
      if err != nil {
         if errors.Is(err, errVisitorExpired) {
            log.Printf("visitor ID expired, clearing from config: %v", err)
            cfg.VisitorID = ""
            saveConfig(configPath, &cfg)
            return
         }
         log.Fatal(err)
      }
   default:
      flag.Usage()
   }
}

// saveConfig writes the config to disk.
func saveConfig(configPath string, cfg *config) {
   if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
      log.Fatalf("cannot create config dir: %v", err)
   }
   data, err := json.MarshalIndent(cfg, "", "  ")
   if err != nil {
      log.Fatalf("cannot marshal config: %v", err)
   }
   if err := os.WriteFile(configPath, data, 0644); err != nil {
      log.Fatalf("cannot write config: %v", err)
   }
}

func write_file(name string, data []byte) error {
   log.Println("WriteFile", name)
   return os.WriteFile(name, data, os.ModePerm)
}

// Helper to handle the repeating logic of formatting and writing JSON
func write_songs(name string, songs []*song) error {
   var buf bytes.Buffer
   enc := json.NewEncoder(&buf)
   enc.SetEscapeHTML(false)
   enc.SetIndent("", " ")
   err := enc.Encode(songs)
   if err != nil {
      return err
   }
   return write_file(name, buf.Bytes())
}

// config is persisted to os.UserConfigDir()/umber/umber.json.
type config struct {
   VisitorID string `json:"visitor_id"`
   InputFile string `json:"input_file"`
}

// song is the on-disk record:
//
//   {"A": [<unix timestamp>, <release year>],
//    "B": [<artist>, <title>, <address>, <image?>]}
type song struct {
   A [2]int64 `json:"A"`
   B []string `json:"B"`
}

// new_song builds a record. The image is appended only when non-empty,
// so the JSON carries no trailing null for tracks without artwork.
func new_song(artist, title, address, image string, timestamp int64, year int) *song {
   b := make([]string, 0, 4)
   b = append(b, artist, title, address)
   if image != "" {
      b = append(b, image)
   }
   return &song{
      A: [2]int64{timestamp, int64(year)},
      B: b,
   }
}

func read_songs(name string) ([]*song, error) {
   data, err := os.ReadFile(name)
   if err != nil {
      return nil, err
   }
   var songs []*song
   err = json.Unmarshal(data, &songs)
   if err != nil {
      return nil, err
   }
   return songs, nil
}
func (s *song) address() string { return s.B[posAddress] }

func (s *song) timestamp() int64 { return s.A[posTime] }

// main.go marker preserve
