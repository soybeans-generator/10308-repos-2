// download.go KEEP THIS LINE
package maya

import (
   "crypto/aes"
   "errors"
   "fmt"
   "io"
   "log"
   "net/http"
   "net/url"
   "time"

   "41.neocities.org/sofia"
)

// errInterrupted reports that a download failed after its output file was
// finalized, so the resume state can be saved just like after a stop.
var errInterrupted = errors.New("download interrupted")

// errStopped reports that the download stopped on request; resume state has
// been saved.
var errStopped = errors.New("download stopped")

// executeSegments downloads segments in order, returning how many were
// written. A stop between segments, or a failed fetch, finalizes the file; a
// stop reports errStopped, a failed fetch errInterrupted, so either way the
// remaining segments are fetched on resume.
func executeSegments(segments []segment, remux *sofia.Remuxer, dst io.Writer, stop <-chan struct{}) (int, error) {
   t := tracker{total: len(segments), start: time.Now(), lastLog: time.Now()}
   for i, seg := range segments {
      if stop != nil {
         select {
         case <-stop:
            if remux != nil {
               if err := remux.Finish(); err != nil {
                  return i, err
               }
            }
            return i, errStopped
         default:
         }
      }
      // The effective URL is irrelevant here: segment URLs are already
      // absolute, so a redirect on one of them changes nothing.
      data, _, err := fetchData(seg.url, seg.headers, false)
      if err != nil {
         return i, finalizeOnError(remux, err)
      }
      if remux != nil {
         if err := remux.AddSegment(data); err != nil {
            return i, err
         }
      } else if _, err := dst.Write(data); err != nil {
         return i, err
      }
      t.update()
   }
   if remux != nil {
      if err := remux.Finish(); err != nil {
         return 0, err
      }
   }
   return len(segments), nil
}

// executeStream downloads a single-URL stream (DASH SegmentBase) with one
// request and hands the body to sofia.Process, so memory holds one segment
// at a time. On a stop the file is finalized and the caller saves the
// resume state from Progress.
func executeStream(seg segment, offset int64, remux *sofia.Remuxer, stop <-chan struct{}) error {
   if remux == nil {
      return errors.New("single-URL download requires a remuxer")
   }
   remux.Stop = stop
   body, contentLength, err := fetchStream(seg.url, offset)
   if err != nil {
      return err
   }
   defer body.Close()

   // A full response starts at 0, a resumed one delivers the remainder,
   // so offset plus content length is the file size either way.
   progress := &progressReader{
      r:      body,
      total:  -1,
      base:   offset,
      done:   offset,
      start:  time.Now(),
      logged: time.Now(),
   }
   if contentLength >= 0 {
      progress.total = offset + contentLength
   }

   processErr := remux.Process(progress)
   if processErr != nil && !errors.Is(processErr, sofia.ErrStopped) {
      // A dropped connection mid-stream is resumable by offset, the same
      // way a stop is: finalize the file and report it as interrupted.
      return finalizeOnError(remux, processErr)
   }
   if err := remux.Finish(); err != nil {
      return err
   }
   if errors.Is(processErr, sofia.ErrStopped) {
      return errStopped
   }
   return nil
}

// fetchStream performs a GET, resuming from offset when it is positive, and
// returns the body with its content length.
func fetchStream(target *url.URL, offset int64) (io.ReadCloser, int64, error) {
   req, err := http.NewRequest(http.MethodGet, target.String(), nil)
   if err != nil {
      return nil, 0, err
   }
   if offset > 0 {
      req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
   }
   log.Println(req.Method, req.URL)

   resp, err := http.DefaultClient.Do(req)
   if err != nil {
      return nil, 0, err
   }
   if offset > 0 {
      // A server that ignores Range answers 200 with the whole body;
      // fail loudly instead of silently re-downloading from the start.
      if resp.StatusCode != http.StatusPartialContent {
         resp.Body.Close()
         return nil, 0, fmt.Errorf("server does not honor Range (got %s)", resp.Status)
      }
   } else if resp.StatusCode != http.StatusOK {
      resp.Body.Close()
      return nil, 0, errors.New(resp.Status)
   }
   return resp.Body, resp.ContentLength, nil
}

// finalizeOnError finishes the output after a failed fetch, so the moov that
// a resume reads back is in place, and marks the failure as resumable. If the
// file cannot be finished there is nothing to resume from, so the original
// error is returned unchanged.
func finalizeOnError(remux *sofia.Remuxer, cause error) error {
   if remux == nil {
      return cause
   }
   if err := remux.Finish(); err != nil {
      log.Printf("finish after error: %v", err)
      return cause
   }
   return fmt.Errorf("%w: %w", errInterrupted, cause)
}

// setDecrypt installs the decryption callback on the remuxer.
func setDecrypt(remux *sofia.Remuxer, key []byte) error {
   if remux == nil || len(key) == 0 {
      return nil
   }
   block, err := aes.NewCipher(key)
   if err != nil {
      return err
   }
   remux.OnSample = func(data []byte, sample *sofia.SencSample) {
      sofia.Decrypt(data, sample, block)
   }
   return nil
}

// progressReader logs MiB progress about once a second as bytes flow through.
type progressReader struct {
   r      io.Reader
   total  int64 // full stream size, or -1 when unknown
   base   int64 // bytes downloaded by earlier sessions
   done   int64 // bytes consumed so far, including base
   start  time.Time
   logged time.Time
}

func (p *progressReader) Read(buf []byte) (int, error) {
   n, err := p.r.Read(buf)
   p.done += int64(n)

   now := time.Now()
   if now.Sub(p.logged) < time.Second {
      return n, err
   }
   rate := float64(p.done-p.base) / now.Sub(p.start).Seconds() / (1 << 20)
   if p.total >= 0 {
      log.Printf("downloaded: %.1f/%.1f MiB (%.2f MiB/s)",
         float64(p.done)/(1<<20), float64(p.total)/(1<<20), rate)
   } else {
      log.Printf("downloaded: %.1f MiB (%.2f MiB/s)", float64(p.done)/(1<<20), rate)
   }
   p.logged = now
   return n, err
}

// tracker logs segment progress at most once a second, and on the last one.
type tracker struct {
   total   int
   done    int
   start   time.Time
   lastLog time.Time
}

func (t *tracker) update() {
   t.done++
   now := time.Now()
   if now.Sub(t.lastLog) < time.Second && t.done != t.total {
      return
   }
   left := t.total - t.done
   elapsed := now.Sub(t.start)
   timeLeft := elapsed / time.Duration(t.done) * time.Duration(left)
   log.Printf("segments done: %d\n\tsegments left: %d\n\ttime elapsed: %v\n\ttime left: %v",
      t.done, left, elapsed.Truncate(time.Second), timeLeft.Truncate(time.Second))
   t.lastLog = now
}

// download.go KEEP THIS LINE
