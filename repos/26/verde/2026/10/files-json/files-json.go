package main

import (
   "bufio"
   "encoding/json"
   "fmt"
   "io/fs"
   "os"
   "path/filepath"
)

const outFile = "files.json"

func main() {
   rootAbs, err := filepath.Abs(".")
   if err != nil {
      fmt.Fprintln(os.Stderr, "error:", err)
      os.Exit(1)
   }
   outAbs, err := filepath.Abs(outFile)
   if err != nil {
      fmt.Fprintln(os.Stderr, "error:", err)
      os.Exit(1)
   }

   f, err := os.Create(outAbs)
   if err != nil {
      fmt.Fprintln(os.Stderr, "error:", err)
      os.Exit(1)
   }
   defer f.Close()

   w := bufio.NewWriter(f)
   defer w.Flush()

   w.WriteString("[")

   first := true
   err = filepath.WalkDir(rootAbs, func(path string, d fs.DirEntry, walkErr error) error {
      if walkErr != nil || d.IsDir() || !d.Type().IsRegular() {
         return nil
      }
      if sameFile(path, outAbs) {
         return nil
      }

      raw, err := os.ReadFile(path)
      if err != nil {
         fmt.Fprintf(os.Stderr, "warn: %v\n", err)
         return nil
      }

      rel, err := filepath.Rel(rootAbs, path)
      if err != nil {
         return nil
      }

      buf, err := json.Marshal(FileEntry{
         Name: filepath.ToSlash(rel),
         Data: string(raw),
      })
      if err != nil {
         return err
      }

      if !first {
         w.WriteString(",")
      }
      first = false
      _, err = w.Write(buf)
      return err
   })
   if err != nil {
      fmt.Fprintln(os.Stderr, "error:", err)
      os.Exit(1)
   }

   w.WriteString("]\n")
   if err := w.Flush(); err != nil {
      fmt.Fprintln(os.Stderr, "error:", err)
      os.Exit(1)
   }
}

func sameFile(path, target string) bool {
   a, err := os.Stat(path)
   if err != nil {
      return false
   }
   b, err := os.Stat(target)
   if err != nil {
      return false
   }
   return os.SameFile(a, b)
}

type FileEntry struct {
   Name string `json:"name"`
   Data string `json:"data"`
}
