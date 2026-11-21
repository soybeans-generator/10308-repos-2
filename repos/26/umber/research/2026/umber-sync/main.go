// main.go KEEP THIS LINE
package main

import (
   "encoding/json"
   "errors"
   "flag"
   "fmt"
   "log"
   "os"
   "path/filepath"
   "strings"
   "time"
)

func configFilePath() (string, error) {
   dir, err := os.UserConfigDir()
   if err != nil {
      return "", fmt.Errorf("config dir: %w", err)
   }
   return filepath.Join(dir, "umber", "umber.json"), nil
}

func cutLeadingCredit(s string) (string, bool) {
   switch {
   case strings.HasPrefix(s, " - "), strings.HasPrefix(s, " | "):
      return s[3:], true
   case strings.HasPrefix(s, ": "):
      return s[2:], true
   }
   return "", false
}

func cutTrailingCredit(s string) (string, bool) {
   switch {
   case strings.HasSuffix(s, " - "), strings.HasSuffix(s, " | "):
      return s[:len(s)-3], true
   case strings.HasSuffix(s, ": "):
      return s[:len(s)-2], true
   }
   return "", false
}

func downloadRecord(r *Record, title, visitorID, outputDir string, threads int, maxETA time.Duration) error {
   p, err := platformOf(r.URL)
   if err != nil {
      return err
   }
   switch p {
   case platformYouTube:
      return downloadYouTube(r, title, visitorID, outputDir, threads, maxETA)
   case platformBandcamp:
      return downloadBandcamp(r, title, outputDir)
   case platformSoundCloud:
      return downloadSoundCloud(r, title, outputDir)
   }
   return nil
}

func main() {
   log.SetFlags(log.Ltime)

   input := flag.String("input", "", "input JSON file (required)")
   output := flag.String("output", "", "output directory (required)")
   threads := flag.Int("threads", 2, "download threads per item")
   maxETA := flag.Duration("max-eta", time.Minute, "skip YouTube items whose ETA exceeds this (0 disables)")
   flag.Parse()

   if *input == "" || *output == "" || *threads < 1 {
      flag.Usage()
      return
   }
   if err := run(*input, *output, *threads, *maxETA); err != nil {
      log.Fatal(err)
   }
}

// pruneFiles deletes files no record claims, plus anything that is not
// audio, and reports which wanted stems already have a non-empty file.
func pruneFiles(outputDir string, wanted map[string]*Record) (map[string]bool, error) {
   entries, err := os.ReadDir(outputDir)
   if err != nil {
      return nil, fmt.Errorf("read output dir: %w", err)
   }
   nonEmpty := make(map[string]bool)
   for _, e := range entries {
      if e.IsDir() {
         continue
      }
      name := e.Name()
      if isTempFile(name) || name == "!playlist.m3u" {
         continue
      }
      path := filepath.Join(outputDir, name)
      switch strings.ToLower(filepath.Ext(name)) {
      case ".opus", ".m4a", ".mp3":
      default:
         removeLogged(path, "not an audio file")
         continue
      }
      stem := strings.TrimSuffix(name, filepath.Ext(name))
      if _, ok := wanted[stem]; !ok {
         removeLogged(path, "not in input")
         continue
      }
      info, err := e.Info()
      if err != nil {
         log.Printf("stat %s: %v", name, err)
         continue
      }
      nonEmpty[stem] = info.Size() > 0
   }
   return nonEmpty, nil
}

func removeLogged(path, reason string) {
   if err := os.Remove(path); err != nil {
      log.Printf("cannot remove %s: %v", path, err)
      return
   }
   log.Printf("removed %s (%s)", path, reason)
}

func removeStaleTemps(outputDir string) error {
   entries, err := os.ReadDir(outputDir)
   if err != nil {
      return fmt.Errorf("read output dir: %w", err)
   }
   var errs []error
   for _, e := range entries {
      if e.IsDir() || !isTempFile(e.Name()) {
         continue
      }
      path := filepath.Join(outputDir, e.Name())
      if err := os.Remove(path); err != nil {
         errs = append(errs, fmt.Errorf("remove %s: %w", path, err))
         continue
      }
      log.Printf("removed temp %s", path)
   }
   return errors.Join(errs...)
}

func run(inputFile, outputDir string, threads int, maxETA time.Duration) error {
   if err := os.MkdirAll(outputDir, 0o755); err != nil {
      return fmt.Errorf("create output dir: %w", err)
   }
   if err := removeStaleTemps(outputDir); err != nil {
      return err
   }

   cfgPath, err := configFilePath()
   if err != nil {
      return err
   }
   cfg, err := loadConfig(cfgPath)
   if err != nil {
      return err
   }
   if cfg.VisitorID == "" {
      log.Print("fetching visitor ID")
      if cfg.VisitorID, err = fetchVisitorID(); err != nil {
         return fmt.Errorf("fetch visitor ID: %w", err)
      }
      log.Print("visitor ID fetched")
      if err := saveConfig(cfgPath, cfg); err != nil {
         return err
      }
   }

   records, err := loadRecords(inputFile)
   if err != nil {
      return err
   }

   stems := countStems(records, outputDir)
   wanted := make(map[string]*Record, len(records))
   for i := range records {
      stem, err := fileStem(&records[i], stems, outputDir)
      if err != nil {
         return err
      }
      if stem != "" {
         wanted[stem] = &records[i]
      }
   }

   nonEmpty, err := pruneFiles(outputDir, wanted)
   if err != nil {
      return err
   }

   pending := 0
   for stem := range wanted {
      if !nonEmpty[stem] {
         pending++
      }
   }

   for stem, rec := range wanted {
      if nonEmpty[stem] {
         continue
      }
      pending--
      log.Printf("downloading (%d queued)", pending)

      err := downloadRecord(rec, stem, cfg.VisitorID, outputDir, threads, maxETA)
      if errors.Is(err, errVisitorExpired) {
         log.Printf("visitor ID expired, resetting: %v", err)
         cfg.VisitorID = ""
         if err := saveConfig(cfgPath, cfg); err != nil {
            log.Printf("save config: %v", err)
         }
         return nil
      }
      if err != nil {
         log.Printf("download %s: %v", stem, err)
      }
   }

   if err := generateM3U(outputDir, records); err != nil {
      log.Printf("playlist: %v", err)
   }
   return nil
}

func saveConfig(path string, cfg *Config) error {
   data, err := json.MarshalIndent(cfg, "", "  ")
   if err != nil {
      return fmt.Errorf("encode config: %w", err)
   }
   if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
      return fmt.Errorf("config dir: %w", err)
   }
   if err := os.WriteFile(path, data, 0o644); err != nil {
      return fmt.Errorf("write config: %w", err)
   }
   return nil
}

type Config struct {
   VisitorID string `json:"visitor_id"`
}

func loadConfig(path string) (*Config, error) {
   data, err := os.ReadFile(path)
   if errors.Is(err, os.ErrNotExist) {
      return &Config{}, nil
   }
   if err != nil {
      return nil, fmt.Errorf("read config: %w", err)
   }
   var cfg Config
   if err := json.Unmarshal(data, &cfg); err != nil {
      return nil, fmt.Errorf("parse config: %w", err)
   }
   return &cfg, nil
}

// Record is one input entry. The source format is two positional arrays:
// A = [added unix seconds, year], B = [author, title, URL, artwork URL?].
type Record struct {
   Author  string
   Title   string
   URL     string
   Artwork string
   Added   int64
   Year    int
}

func loadRecords(path string) ([]Record, error) {
   data, err := os.ReadFile(path)
   if err != nil {
      return nil, fmt.Errorf("read input: %w", err)
   }
   var records []Record
   if err := json.Unmarshal(data, &records); err != nil {
      return nil, fmt.Errorf("parse input: %w", err)
   }
   return records, nil
}

func (r *Record) UnmarshalJSON(data []byte) error {
   var raw struct {
      A []json.RawMessage `json:"A"`
      B []string          `json:"B"`
   }
   if err := json.Unmarshal(data, &raw); err != nil {
      return err
   }
   if len(raw.A) != 2 {
      return fmt.Errorf("field A: got %d values, want 2", len(raw.A))
   }
   if len(raw.B) < 3 {
      return fmt.Errorf("field B: got %d values, want at least 3", len(raw.B))
   }
   if err := json.Unmarshal(raw.A[0], &r.Added); err != nil {
      return fmt.Errorf("field A[0]: %w", err)
   }
   if err := json.Unmarshal(raw.A[1], &r.Year); err != nil {
      return fmt.Errorf("field A[1]: %w", err)
   }
   r.Author, r.Title, r.URL = raw.B[0], raw.B[1], raw.B[2]
   if len(raw.B) > 3 {
      r.Artwork = raw.B[3]
   }
   return nil
}

// artist is the author with a YouTube topic-channel suffix removed.
func (r *Record) artist() string {
   if strings.HasPrefix(r.URL, "https://youtube.com/") && strings.HasSuffix(r.Author, " - Topic") {
      return strings.TrimSuffix(r.Author, " - Topic")
   }
   return r.Author
}

// displayName is the file name stem: the title alone when it already
// credits the author, otherwise "artist - title".
func (r *Record) displayName() string {
   if strings.Contains(strings.ToLower(r.Title), strings.ToLower(r.Author)) {
      return r.Title
   }
   return r.artist() + " - " + r.Title
}

// trackTitle is the title tag: a leading or trailing author credit is
// dropped together with its separator.
func (r *Record) trackTitle() string {
   author, title := r.Author, r.Title
   n := len(author)
   if n >= len(title) {
      return title
   }
   if strings.EqualFold(title[:n], author) {
      if rest, ok := cutLeadingCredit(title[n:]); ok {
         return rest
      }
   }
   if strings.EqualFold(title[len(title)-n:], author) {
      if head, ok := cutTrailingCredit(title[:len(title)-n]); ok {
         return head
      }
   }
   return title
}

// main.go KEEP THIS LINE
