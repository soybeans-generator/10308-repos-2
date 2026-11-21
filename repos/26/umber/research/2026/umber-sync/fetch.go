// fetch.go KEEP THIS LINE
package main

import (
   "bytes"
   "errors"
   "fmt"
   "io"
   "log"
   "net/http"
   "net/url"
   "os"
   "os/exec"
   "path/filepath"
   "strconv"
   "strings"
   "sync"
   "sync/atomic"
   "time"
)

func baseStem(path string) string {
   return strings.TrimSuffix(filepath.Base(path), ".part")
}

func commit(rawPath, taggedPath, finalPath string) error {
   if err := os.Remove(rawPath); err != nil && !errors.Is(err, os.ErrNotExist) {
      return fmt.Errorf("remove raw file: %w", err)
   }
   if err := os.Rename(taggedPath, finalPath); err != nil {
      return fmt.Errorf("rename output: %w", err)
   }
   return nil
}

// downloadFile fetches with parallel range requests when the server allows
// them, and falls back to a single-stream download otherwise.
func downloadFile(streamURL, path string, threads int, maxETA time.Duration) error {
   total, ranged, err := remoteSize(streamURL)
   if err != nil {
      return err
   }
   if !ranged || threads < 2 {
      return downloadFileSingle(streamURL, path, maxETA)
   }
   return downloadRanged(streamURL, path, total, threads, maxETA)
}

// downloadFileSingle streams the whole body in one request. A maxETA of 0
// or less disables the ETA limit.
func downloadFileSingle(streamURL, path string, maxETA time.Duration) error {
   resp, err := http.Get(streamURL)
   if err != nil {
      return fmt.Errorf("request: %w", err)
   }
   defer resp.Body.Close()
   if resp.StatusCode != http.StatusOK {
      return fmt.Errorf("download: %s", resp.Status)
   }

   f, err := os.Create(path)
   if err != nil {
      return fmt.Errorf("create file: %w", err)
   }
   defer f.Close()

   total := resp.ContentLength
   start := time.Now()
   last := start
   var received int64
   buf := make([]byte, 32<<10)
   for {
      n, rerr := resp.Body.Read(buf)
      if n > 0 {
         if _, werr := f.Write(buf[:n]); werr != nil {
            return fmt.Errorf("write file: %w", werr)
         }
         received += int64(n)
         if now := time.Now(); now.Sub(last) >= time.Second {
            last = now
            elapsed := now.Sub(start)
            logTransfer(path, received, total, elapsed)
            eta, known := etaFor(received, total, elapsed)
            if maxETA > 0 && known && eta > maxETA && elapsed > 2*time.Second {
               return fmt.Errorf("eta limit exceeded: projected %s over %s", eta.Round(time.Millisecond), maxETA)
            }
         }
      }
      if rerr == io.EOF {
         break
      }
      if rerr != nil {
         return fmt.Errorf("read body: %w", rerr)
      }
   }
   log.Printf("%s  done  %s in %s", baseStem(path), formatBytes(received), time.Since(start).Round(time.Millisecond))
   return nil
}

func downloadRanged(streamURL, path string, total int64, threads int, maxETA time.Duration) error {
   f, err := os.Create(path)
   if err != nil {
      return fmt.Errorf("create file: %w", err)
   }
   defer f.Close()
   if err := f.Truncate(total); err != nil {
      return fmt.Errorf("size file: %w", err)
   }

   stop := make(chan struct{})
   var once sync.Once
   halt := func() { once.Do(func() { close(stop) }) }
   defer halt()

   var (
      received atomic.Int64
      skipETA  atomic.Bool
      workers  sync.WaitGroup
      watcher  sync.WaitGroup
      errOnce  sync.Once
      fetchErr error
   )
   fail := func(err error) {
      errOnce.Do(func() { fetchErr = err })
      halt()
   }

   start := time.Now()
   width := (total + int64(threads) - 1) / int64(threads)
   for i := 0; i < threads; i++ {
      first := int64(i) * width
      last := min(first+width-1, total-1)
      if first > last {
         break
      }
      workers.Add(1)
      go func(first, last int64) {
         defer workers.Done()
         if err := fetchRange(f, streamURL, first, last, &received, stop); err != nil {
            fail(err)
         }
      }(first, last)
   }

   watcher.Add(1)
   go func() {
      defer watcher.Done()
      ticker := time.NewTicker(time.Second)
      defer ticker.Stop()
      for {
         select {
         case <-stop:
            return
         case now := <-ticker.C:
            elapsed := now.Sub(start)
            done := received.Load()
            logTransfer(path, done, total, elapsed)
            eta, known := etaFor(done, total, elapsed)
            if maxETA > 0 && known && eta > maxETA && elapsed > 2*time.Second {
               skipETA.Store(true)
               halt()
               return
            }
         }
      }
   }()

   workers.Wait()
   halt()
   watcher.Wait()

   if skipETA.Load() {
      return fmt.Errorf("eta limit exceeded: over %s", maxETA)
   }
   if fetchErr != nil {
      return fetchErr
   }
   log.Printf("%s  done  %s in %s", baseStem(path), formatBytes(total), time.Since(start).Round(time.Millisecond))
   return nil
}

func etaFor(done, total int64, elapsed time.Duration) (time.Duration, bool) {
   if done <= 0 || total <= 0 || done >= total || elapsed <= 0 {
      return 0, false
   }
   rate := float64(done) / elapsed.Seconds()
   if rate <= 0 {
      return 0, false
   }
   return time.Duration(float64(total-done) / rate * float64(time.Second)), true
}

// fetchRange writes one byte range into f at its own offset. It stops
// early, returning nil, once stop is closed: a canceled transfer's cause
// is reported by whoever closed stop, not by the worker.
func fetchRange(f *os.File, streamURL string, first, last int64, received *atomic.Int64, stop <-chan struct{}) error {
   req, err := http.NewRequest(http.MethodGet, streamURL, nil)
   if err != nil {
      return err
   }
   req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", first, last))

   resp, err := http.DefaultClient.Do(req)
   if err != nil {
      return err
   }
   defer resp.Body.Close()
   if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
      return fmt.Errorf("range %d-%d: %s", first, last, resp.Status)
   }

   buf := make([]byte, 32<<10)
   offset := first
   for {
      select {
      case <-stop:
         return nil
      default:
      }

      n, rerr := resp.Body.Read(buf)
      if n > 0 {
         if _, werr := f.WriteAt(buf[:n], offset); werr != nil {
            return fmt.Errorf("write file: %w", werr)
         }
         offset += int64(n)
         received.Add(int64(n))
      }
      if rerr == io.EOF {
         return nil
      }
      if rerr != nil {
         return fmt.Errorf("read body: %w", rerr)
      }
   }
}

func formatBytes(n int64) string {
   if n < 0 {
      return "?"
   }
   const units = "KMGTPE"
   div, exp := int64(1), 0
   for n/div >= 1024 && exp < len(units) {
      div *= 1024
      exp++
   }
   if exp == 0 {
      return fmt.Sprintf("%d B", n)
   }
   return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), units[exp-1])
}

func logTransfer(path string, done, total int64, elapsed time.Duration) {
   eta := "unknown"
   if d, ok := etaFor(done, total, elapsed); ok {
      eta = d.Round(time.Millisecond).String()
   }
   log.Printf("%s  %s / %s  elapsed %s  eta %s",
      baseStem(path), formatBytes(done), formatBytes(total), elapsed.Round(time.Millisecond), eta)
}

// recordID is the URL-derived disambiguator: the video ID for YouTube, the
// last path segment for Bandcamp and SoundCloud.
func recordID(p platform, rawURL string) (string, error) {
   switch p {
   case platformYouTube:
      return videoID(rawURL)
   case platformBandcamp, platformSoundCloud:
      u, err := url.Parse(rawURL)
      if err != nil {
         return "", fmt.Errorf("parse url: %w", err)
      }
      path := strings.Trim(u.Path, "/")
      if i := strings.LastIndexByte(path, '/'); i >= 0 {
         return path[i+1:], nil
      }
      return path, nil
   }
   return "", nil
}

func remoteSize(streamURL string) (total int64, ranged bool, err error) {
   req, err := http.NewRequest(http.MethodGet, streamURL, nil)
   if err != nil {
      return 0, false, err
   }
   req.Header.Set("Range", "bytes=0-0")

   resp, err := http.DefaultClient.Do(req)
   if err != nil {
      return 0, false, fmt.Errorf("probe: %w", err)
   }
   defer resp.Body.Close()
   io.Copy(io.Discard, resp.Body)

   _, size, ok := strings.Cut(resp.Header.Get("Content-Range"), "/")
   if !ok {
      return 0, false, nil
   }
   total, err = strconv.ParseInt(size, 10, 64)
   if err != nil || total <= 0 {
      return 0, false, nil
   }
   return total, true, nil
}

func removeFiles(paths ...string) {
   for _, path := range paths {
      if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
         log.Printf("cannot remove %s: %v", path, err)
      }
   }
}

// remuxTagged stream-copies src to dst while writing artist and title
// tags. The muxer follows dst's extension.
func remuxTagged(src, dst string, r *Record) error {
   cmd := exec.Command("ffmpeg",
      "-i", src,
      "-c", "copy",
      "-metadata", "artist="+r.artist(),
      "-metadata", "title="+r.trackTitle(),
      dst,
   )
   var stderr bytes.Buffer
   cmd.Stderr = &stderr
   if err := cmd.Run(); err != nil {
      return fmt.Errorf("ffmpeg: %w\n%s", err, stderr.String())
   }
   return nil
}

// saveTrack runs the shared pipeline: download the stream, tag it with
// ffmpeg, then move the result into place.
func saveTrack(streamURL string, r *Record, title, ext, outputDir string, download func(url, path string) error) (err error) {
   name := sanitizeFilename(title, outputDir)
   finalPath := filepath.Join(outputDir, name+ext)
   rawPath := filepath.Join(outputDir, name+".part")
   taggedPath := filepath.Join(outputDir, name+".remux."+ext)

   defer func() {
      if err != nil {
         removeFiles(rawPath, taggedPath)
      }
   }()

   if err = download(streamURL, rawPath); err != nil {
      return err
   }
   if err = remuxTagged(rawPath, taggedPath, r); err != nil {
      return err
   }
   if err = commit(rawPath, taggedPath, finalPath); err != nil {
      return err
   }
   log.Printf("%s  ready", filepath.Base(finalPath))
   return nil
}

func supported(p platform) bool {
   return p == platformBandcamp || p == platformYouTube || p == platformSoundCloud
}

type platform int

const (
   platformOther platform = iota
   platformBandcamp
   platformYouTube
   platformSoundCloud
)

func platformOf(rawURL string) (platform, error) {
   u, err := url.Parse(rawURL)
   if err != nil {
      return platformOther, fmt.Errorf("parse url: %w", err)
   }
   host := strings.ToLower(u.Hostname())
   switch {
   case host == "youtube.com":
      return platformYouTube, nil
   case host == "bandcamp.com" || strings.HasSuffix(host, ".bandcamp.com"):
      return platformBandcamp, nil
   case host == "soundcloud.com" || strings.HasSuffix(host, ".soundcloud.com"):
      return platformSoundCloud, nil
   }
   return platformOther, nil
}

// fetch.go KEEP THIS LINE
