package main

import (
   "flag"
   "fmt"
   "log"
   "os"
   "path/filepath"
   "strings"
)

func countLOC(name string) (int, error) {
   b, err := os.ReadFile(name)
   if err != nil {
      return 0, err
   }
   lines := strings.Split(strings.TrimSpace(string(b)), "\n")
   n := 0
   for _, l := range lines {
      t := strings.TrimSpace(l)
      if t != "" && !strings.HasPrefix(t, "//") {
         n++
      }
   }
   return n, nil
}

func main() {
   dir := flag.String("dir", ".", "directory to scan")
   flag.Parse()

   total := 0
   err := filepath.WalkDir(*dir, func(path string, d os.DirEntry, err error) error {
      if err != nil {
         return err
      }
      if d.IsDir() || filepath.Ext(path) != ".go" {
         return nil
      }
      n, err := countLOC(path)
      if err != nil {
         return err
      }
      fmt.Printf("%s: %d\n", path, n)
      total += n
      return nil
   })
   if err != nil {
      log.Fatal(err)
   }
   fmt.Printf("total: %d\n", total)
}
