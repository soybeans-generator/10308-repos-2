// naming.go KEEP THIS LINE
package main

import (
   "cmp"
   "fmt"
   "log"
   "os"
   "path/filepath"
   "slices"
   "strings"
   "unicode/utf8"
)

// audioFiles maps every finished file's stem to its name.
func audioFiles(dir string) (map[string]string, error) {
   entries, err := os.ReadDir(dir)
   if err != nil {
      return nil, fmt.Errorf("read output dir: %w", err)
   }
   files := make(map[string]string)
   for _, e := range entries {
      if e.IsDir() {
         continue
      }
      name := e.Name()
      if isTempFile(name) || strings.HasSuffix(name, ".m3u") {
         continue
      }
      files[strings.TrimSuffix(name, filepath.Ext(name))] = name
   }
   return files, nil
}

// countStems maps a lowercased filename stem to the number of records that
// sanitize to it. Extensions never matter, so a .mp3 and an .opus sharing a
// stem count as a collision.
func countStems(records []Record, outputDir string) map[string]int {
   counts := make(map[string]int, len(records))
   for i := range records {
      stem := sanitizeFilename(records[i].displayName(), outputDir)
      counts[strings.ToLower(stem)]++
   }
   return counts
}

// fileStem returns the stem for r, appending the record ID when another
// record shares the stem. An empty stem means the platform is unsupported.
func fileStem(r *Record, counts map[string]int, outputDir string) (string, error) {
   p, err := platformOf(r.URL)
   if err != nil {
      return "", fmt.Errorf("record %q: %w", r.Title, err)
   }
   if !supported(p) {
      return "", nil
   }

   stem := sanitizeFilename(r.displayName(), outputDir)
   if counts[strings.ToLower(stem)] < 2 {
      return stem, nil
   }
   id, err := recordID(p, r.URL)
   if err != nil {
      return "", fmt.Errorf("record %q: %w", r.Title, err)
   }
   if id == "" {
      return stem, nil
   }
   return sanitizeFilename(stem+" "+id, outputDir), nil
}

// foldAstral rewrites astral runes, which HiBy players reject:
// mathematical alphanumerics become ASCII, everything else astral is
// dropped along with the zero-width joiners it leaves behind.
func foldAstral(s string) string {
   var b strings.Builder
   b.Grow(len(s))
   for _, r := range s {
      switch {
      case r <= 0xFFFF:
         if r != '\u200d' && r != '\ufe0f' {
            b.WriteRune(r)
         }
      case r >= 0x1D400 && r <= 0x1D6A3:
         off := (r - 0x1D400) % 52
         if off < 26 {
            b.WriteRune('A' + off)
         } else {
            b.WriteRune('a' + off - 26)
         }
      case r >= 0x1D7CE && r <= 0x1D7FF:
         b.WriteRune('0' + (r-0x1D7CE)%10)
      }
   }
   return b.String()
}

func generateM3U(outputDir string, records []Record) error {
   stems := countStems(records, outputDir)

   var tracks []*Record
   for i := range records {
      p, err := platformOf(records[i].URL)
      if err != nil {
         return fmt.Errorf("record %q: %w", records[i].Title, err)
      }
      if supported(p) {
         tracks = append(tracks, &records[i])
      }
   }
   slices.SortFunc(tracks, func(a, b *Record) int {
      return cmp.Compare(b.Added, a.Added)
   })

   files, err := audioFiles(outputDir)
   if err != nil {
      return err
   }

   var b strings.Builder
   b.WriteString("#EXTM3U\n")
   count := 0
   for _, t := range tracks {
      stem, err := fileStem(t, stems, outputDir)
      if err != nil {
         return err
      }
      if stem == "" {
         continue
      }
      name, ok := files[stem]
      if !ok {
         continue
      }
      b.WriteString(name)
      b.WriteByte('\n')
      count++
   }

   path := filepath.Join(outputDir, "!playlist.m3u")
   if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
      return fmt.Errorf("write playlist: %w", err)
   }
   log.Printf("playlist %s (%d tracks)", path, count)
   return nil
}

// isTempFile reports whether name is an in-flight file: <stem>.part (raw
// download) or <stem>.remux.<ext> (ffmpeg output). The old .tmp and .t
// suffixes are still recognized so leftovers from earlier runs get cleaned.
func isTempFile(name string) bool {
   if strings.HasSuffix(name, ".part") || strings.HasSuffix(name, ".tmp") || strings.HasSuffix(name, ".t") {
      return true
   }
   i := strings.LastIndexByte(name, '.')
   return i >= 0 && strings.HasSuffix(name[:i], ".remux.")
}

// sanitizeFilename replaces characters filesystems reject, strips trailing
// dots and spaces, and truncates so the path stays within Windows limits.
func sanitizeFilename(s, outputDir string) string {
   if strings.ContainsFunc(s, func(r rune) bool { return r > 0xFFFF }) {
      s = foldAstral(s)
   }
   s = strings.Map(func(r rune) rune {
      if strings.ContainsRune(`\/:*?"<>|`, r) {
         return '_'
      }
      return r
   }, s)
   s = strings.TrimRight(s, ". ")

   reserved := len(".opus")
   limit := min(255-reserved, 259-len(outputDir)-1-reserved)
   if limit < 1 {
      limit = 1
   }
   if len(s) > limit {
      s = s[:limit]
      for !utf8.ValidString(s) {
         s = s[:len(s)-1]
      }
      s = strings.TrimRight(s, ". ")
   }
   return s
}

// naming.go KEEP THIS LINE
