// orchestrator.go KEEP THIS LINE
package maya

import (
   "encoding/binary"
   "encoding/hex"
   "errors"
   "fmt"
   "io"
   "log"
   "os"

   "41.neocities.org/playReady"
   "41.neocities.org/sofia"
   "41.neocities.org/widevine"
)

// StopKey enables the interactive stop: press q to finish the download
// cleanly and save its resume state. Set it to false when stdin is not a
// keyboard. One download per process is assumed; it is read at start.
var StopKey = true

// orchestrateDownload runs a download from opening the output file to
// finishing or stopping it. A stop saves the resume state (fMP4 only), and
// running the same command again picks it up.
func orchestrateDownload(job *downloadJob) error {
   if job.single != nil && !job.info.IsFmp4 {
      return errors.New("single-URL downloads require fMP4")
   }
   stop := stopSignal()
   if stop != nil && job.info.IsFmp4 {
      log.Println("press q (then Enter) to stop the download cleanly and save resume state")
   }

   outputName := job.outputFileNameBase + job.info.Extension
   file, state, err := openOutput(outputName)
   if err != nil {
      return err
   }
   defer file.Close()

   var remux *sofia.Remuxer
   var key []byte

   if job.info.IsFmp4 {
      switch {
      case job.single != nil && state.Segments == 0:
         // Fresh single-URL download: the remuxer consumes the moov
         // from the stream itself, so the key is fetched there, before
         // the first segment is decrypted. key is captured so the stop
         // path can save it.
         remux = &sofia.Remuxer{Writer: file}
         if job.fetchKey != nil {
            remux.OnMoov = func(moov *sofia.MoovBox) error {
               protection, err := extractProtection(moov)
               if err != nil {
                  return err
               }
               fetched, err := getKeyForStream(job.fetchKey, job.manifestProtection, protection)
               if err != nil {
                  return err
               }
               key = fetched
               return setDecrypt(remux, key)
            }
         }
      default:
         initData := job.initSegmentData
         if job.single != nil {
            // Resumed single-URL download: the resume offset is past
            // the moov, so the init bytes are fetched now.
            if job.fetchInit == nil {
               return errors.New("resumed download requires an init fetcher")
            }
            initData, err = job.fetchInit()
            if err != nil {
               return err
            }
         }
         var protection *protectionInfo
         remux, protection, err = newRemuxer(initData, file, state.Segments)
         if err != nil {
            return err
         }
         if job.fetchKey != nil {
            if len(state.Key) > 0 {
               key = state.Key
               log.Println("resume: using saved decryption key")
            } else if key, err = getKeyForStream(job.fetchKey, job.manifestProtection, protection); err != nil {
               return err
            }
         }
         if err := setDecrypt(remux, key); err != nil {
            return err
         }
      }
   }

   if state.Segments > 0 {
      if job.single != nil {
         log.Printf("resume: continuing at byte %d", state.Offset)
      } else {
         log.Printf("resume: skipping %d/%d already-downloaded segments", state.Segments, len(job.allRequests))
      }
   }

   var segmentsDone int
   var runErr error
   if job.single != nil {
      runErr = executeStream(*job.single, state.Offset, remux, stop)
   } else {
      segmentsDone, runErr = executeSegments(job.allRequests[state.Segments:], remux, file, stop)
   }

   switch {
   case errors.Is(runErr, errStopped):
      if !job.info.IsFmp4 {
         // Raw streams keep no resume state; the partial output must be
         // deleted to start over.
         log.Println("stop: raw streams are not resumable; delete the output to start over")
         return nil
      }
      resume := &resumeState{Key: key}
      if job.single != nil {
         // Progress is relative to the first byte this session read.
         offset, segments := remux.Progress()
         resume.Segments = segments
         resume.Offset = state.Offset + offset
      } else {
         resume.Segments = state.Segments + segmentsDone
      }
      if resume.Segments == 0 {
         log.Println("stop: nothing downloaded yet; delete the output to start over")
         return nil
      }
      if err := writeResume(outputName+".json", resume); err != nil {
         return err
      }
      log.Println("stop: resume state saved; run again to resume")
      return nil
   case runErr != nil:
      return runErr
   default:
      // Finished: drop the state left behind by an earlier stop.
      if err := os.Remove(outputName + ".json"); err != nil && !errors.Is(err, os.ErrNotExist) {
         return err
      }
      return nil
   }
}

// readStoppedMoov reads the moov that a stop appended after the media data
// and returns it with the offset where the payloads end. Only the mdat
// header and the moov are read; the media data never enters memory.
func readStoppedMoov(file *os.File) ([]byte, int64, error) {
   header := make([]byte, 16)
   if _, err := file.ReadAt(header, 0); err != nil {
      return nil, 0, fmt.Errorf("read mdat header: %w", err)
   }
   if string(header[4:8]) != "mdat" {
      return nil, 0, errors.New("output file does not contain an mdat box; delete it and the resume state to start over")
   }

   // Finish patched the extended size field with the full box size, which
   // is also where the moov begins.
   payloadEnd := int64(binary.BigEndian.Uint64(header[8:16]))
   if payloadEnd < 16 {
      return nil, 0, errors.New("output file was not finalized; delete it and the resume state to start over")
   }

   info, err := file.Stat()
   if err != nil {
      return nil, 0, err
   }
   if info.Size() <= payloadEnd {
      return nil, 0, errors.New("output file has no moov to resume from; delete it and the resume state to start over")
   }

   moovData := make([]byte, info.Size()-payloadEnd)
   if _, err := file.ReadAt(moovData, payloadEnd); err != nil {
      return nil, 0, err
   }
   return moovData, payloadEnd, nil
}

// stopSignal starts reading stdin for this download and returns its stop
// channel, or nil when StopKey is false. Receiving from a nil channel blocks
// forever, so "disabled" means "never stop" with no other machinery.
func stopSignal() <-chan struct{} {
   if !StopKey {
      return nil
   }
   stop := make(chan struct{})
   go func() {
      buf := make([]byte, 1)
      for {
         n, err := os.Stdin.Read(buf)
         if err != nil || n == 0 {
            return
         }
         if buf[0] == 'q' {
            close(stop)
            return
         }
      }
   }()
   return stop
}

// extractProtection reads the DRM identifiers out of a moov: the content ID
// from the Widevine or PlayReady pssh, and the default KID from the track's
// tenc box.
func extractProtection(moov *sofia.MoovBox) (*protectionInfo, error) {
   if moov == nil {
      return nil, nil
   }
   protection := &protectionInfo{}

   widevineId, err := hex.DecodeString(widevineSystemID)
   if err != nil {
      return nil, fmt.Errorf("decode widevine system ID: %w", err)
   }
   playReadyId, err := hex.DecodeString(playReadySystemID)
   if err != nil {
      return nil, fmt.Errorf("decode playready system ID: %w", err)
   }

   if pssh, ok := moov.FindPssh(widevineId); ok {
      if data, err := widevine.DecodePsshData(pssh.Data); err == nil {
         protection.ContentId = data.ContentId
      }
   }
   if protection.ContentId == nil {
      if pssh, ok := moov.FindPssh(playReadyId); ok {
         pro, err := playReady.ParsePro(pssh.Data)
         if err != nil {
            return nil, fmt.Errorf("parse PlayReady PRO: %w", err)
         }
         if pro.Data.CustomAttributes != nil {
            protection.ContentId = []byte(pro.Data.CustomAttributes.ContentId)
         }
      }
   }

   protection.KeyId = moov.FindDefaultKID()
   return protection, nil
}

// newRemuxer prepares the remuxer, either fresh from initData or resumed
// from the moov a previous stop appended to the output file. That moov is
// read back with bounded memory and truncated away, so new fragments append
// exactly where the old ones ended.
func newRemuxer(initData []byte, file *os.File, segmentsDone int) (*sofia.Remuxer, *protectionInfo, error) {
   remux := &sofia.Remuxer{Writer: file}

   if segmentsDone > 0 {
      moovData, payloadEnd, err := readStoppedMoov(file)
      if err != nil {
         return nil, nil, err
      }
      state, err := sofia.StateFromMoov(moovData)
      if err != nil {
         return nil, nil, fmt.Errorf("rebuild remux state from %s: %w", file.Name(), err)
      }
      if err := remux.AdoptState(initData, state, segmentsDone); err != nil {
         return nil, nil, err
      }
      if err := file.Truncate(payloadEnd); err != nil {
         return nil, nil, err
      }
      if _, err := file.Seek(payloadEnd, io.SeekStart); err != nil {
         return nil, nil, err
      }
   } else if len(initData) > 0 {
      if err := remux.Initialize(initData); err != nil {
         return nil, nil, err
      }
   }

   if remux.Moov == nil {
      return remux, nil, nil
   }
   protection, err := extractProtection(remux.Moov)
   if err != nil {
      return nil, nil, err
   }
   return remux, protection, nil
}

// downloadJob describes everything needed to run one download.
type downloadJob struct {
   outputFileNameBase string
   info               *typeInfo
   allRequests        []segment
   // single is a whole stream behind one URL (DASH SegmentBase),
   // downloaded with one request and resumable by byte offset.
   single *segment
   // fetchInit fetches the initialization bytes on demand. Only a resumed
   // single-URL download needs it: its offset already lies past the moov
   // at the front of the stream.
   fetchInit          func() ([]byte, error)
   initSegmentData    []byte
   manifestProtection *protectionInfo
   fetchKey           keyFetcher
}

// segment is one chunk to download.
type segment struct {
   url      string
   headers  map[string]string
   duration float64
}

// typeInfo holds the properties of a stream.
type typeInfo struct {
   Extension string
   IsFmp4    bool
}

// orchestrator.go KEEP THIS LINE
