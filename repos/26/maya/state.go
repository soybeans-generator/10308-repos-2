// state.go KEEP THIS LINE
package maya

import (
   "encoding/json"
   "encoding/xml"
   "errors"
   "fmt"
   "log"
   "os"
   "path/filepath"
)

func writeResume(name string, state *resumeState) error {
   data, err := json.Marshal(state)
   if err != nil {
      return err
   }
   return os.WriteFile(name, data, 0o666)
}

// Cache is a directory holding one file per cached value.
type Cache string

func (c Cache) Decode(values ...CacheValue) error {
   for _, value := range values {
      name := filepath.Join(string(c), value.CachePath())
      data, err := os.ReadFile(name)
      if err != nil {
         return err
      }
      if err := xml.Unmarshal(data, value); err != nil {
         return fmt.Errorf("decode %T: %w", value, err)
      }
   }
   return nil
}

func (c Cache) Encode(values ...CacheValue) error {
   for _, value := range values {
      data, err := xml.MarshalIndent(value, "", "  ")
      if err != nil {
         return fmt.Errorf("encode %T: %w", value, err)
      }
      name := filepath.Join(string(c), value.CachePath())
      if err := os.MkdirAll(filepath.Dir(name), os.ModePerm); err != nil {
         return err
      }
      log.Println("create:", name)
      if err := os.WriteFile(name, data, os.ModePerm); err != nil {
         return err
      }
   }
   return nil
}

func (c *Cache) Setup() error {
   dir, err := os.UserCacheDir()
   if err != nil {
      return err
   }
   *c = Cache(dir)
   return nil
}

// CacheValue can be stored in a Cache.
type CacheValue interface {
   CachePath() string
}

// resumeState is the sidecar (<output>.json) written next to an fMP4 output
// when a download is stopped, so that running the same command again
// resumes. Segments counts the segments already written, Key is the
// decryption key when the stream was decrypted, and Offset is the byte
// position of a single-URL stream. The sample tables live in the moov the
// stop appends to the output file itself.
type resumeState struct {
   Segments int    `json:"segments"`
   Key      []byte `json:"key,omitempty"`
   Offset   int64  `json:"offset,omitempty"`
}

// openOutput opens the output file for writing, resuming from an existing
// sidecar when there is one. Trimming a stopped file back to its payload
// boundary happens later, once the moov has been read back.
func openOutput(name string) (*os.File, *resumeState, error) {
   state, err := readResume(name + ".json")
   if err != nil {
      return nil, nil, err
   }
   if state != nil {
      file, err := os.OpenFile(name, os.O_RDWR, 0)
      if err != nil {
         return nil, nil, fmt.Errorf("resume state exists but %s cannot be opened; delete the state to start over", name)
      }
      return file, state, nil
   }
   if fi, err := os.Stat(name); err == nil && fi.Size() > 0 {
      return nil, nil, fmt.Errorf("%s already exists and no resume state was found; delete it to start over", name)
   }
   if err := os.MkdirAll(filepath.Dir(name), os.ModePerm); err != nil {
      return nil, nil, err
   }
   log.Println("create:", name)
   file, err := os.Create(name)
   return file, &resumeState{}, err
}

func readResume(name string) (*resumeState, error) {
   data, err := os.ReadFile(name)
   if errors.Is(err, os.ErrNotExist) {
      return nil, nil
   }
   if err != nil {
      return nil, err
   }
   var state resumeState
   if err := json.Unmarshal(data, &state); err != nil || state.Segments < 0 {
      return nil, fmt.Errorf("resume state %s is corrupt; delete it to start over", name)
   }
   return &state, nil
}

// state.go KEEP THIS LINE
