// goloc.go

// Command goloc reports, for every directory in the working directory's tree,
// how many lines of Go code live directly in that directory. Subdirectories are
// visited, but their lines are never rolled up into a parent.
//
// Only directories that declare package main and import net/http in at least one
// of their own .go files are reported. A line is counted only when it holds at
// least one character that is neither whitespace nor part of a comment.
//
// The line counting, package clause and import detection live in count.go.
//
// Usage:
//
//   go run goloc.go count.go
package main

import (
   "cmp"
   "fmt"
   "io/fs"
   "log"
   "os"
   "path/filepath"
   "slices"
   "strconv"
   "strings"
)

// targetImport is the import path a directory must contain to be reported.
const targetImport = "net/http"

// targetPackage is the package clause a directory must contain to be reported.
const targetPackage = "main"

func main() {
   log.SetPrefix("goloc: ")
   log.SetFlags(0)

   if err := run(); err != nil {
      log.Fatal(err)
   }
}

// relativePath renders path relative to root for display.
func relativePath(root, path string) string {
   rel, err := filepath.Rel(root, path)
   if err != nil {
      return path
   }
   if rel == "." {
      rel = "." + string(filepath.Separator)
   }

   return filepath.ToSlash(rel)
}

// resolveRoot returns the absolute path of the working directory to scan.
func resolveRoot() (string, error) {
   root, err := filepath.Abs(".")
   if err != nil {
      return "", err
   }

   fi, err := os.Stat(root)
   if err != nil {
      return "", err
   }
   if !fi.IsDir() {
      return "", fmt.Errorf("%s is not a directory", root)
   }

   return root, nil
}

// run resolves the root, scans the tree, selects the rows to report and prints
// them.
func run() error {
   root, err := resolveRoot()
   if err != nil {
      return err
   }

   stats, err := scanTree(root)
   if err != nil {
      return err
   }

   return writeTable(selectRows(stats, root), len(stats))
}

// writeTable prints the rows as an aligned text table with a totals line.
func writeTable(rows []*dirStat, scanned int) error {
   totalLOC := 0
   totalFiles := 0

   for _, s := range rows {
      totalLOC += s.loc
      totalFiles += s.files
   }

   widthLOC := len(strconv.Itoa(totalLOC))
   widthFiles := len(strconv.Itoa(totalFiles))
   for _, s := range rows {
      if n := len(strconv.Itoa(s.loc)); n > widthLOC {
         widthLOC = n
      }
      if n := len(strconv.Itoa(s.files)); n > widthFiles {
         widthFiles = n
      }
   }

   fmt.Printf("%*s  %*s  %s\n", widthLOC, "LOC", widthFiles, "FILES", "DIRECTORY")

   for _, s := range rows {
      fmt.Printf("%*d  %*d  %s\n", widthLOC, s.loc, widthFiles, s.files, s.rel)
   }

   fmt.Printf("%*s  %*s  %s\n",
      widthLOC, strings.Repeat("-", widthLOC),
      widthFiles, strings.Repeat("-", widthFiles),
      "---------")

   _, err := fmt.Printf("%*d  %*d  total package %s lines importing %s in %d directories (%d scanned)\n",
      widthLOC, totalLOC, widthFiles, totalFiles, targetPackage, targetImport, len(rows), scanned)

   return err
}

// dirStat holds the tally for a single directory: its own files only.
type dirStat struct {
   path    string // absolute
   rel     string // relative to the scanned root, forward slashes
   loc     int    // counted code lines
   files   int    // counted .go files
   mainPkg bool   // a file in it declares package main
   httpImp bool   // a file in it imports targetImport
}

// scanTree walks the tree and records one dirStat per directory, counting only
// the .go files that sit directly in it.
func scanTree(root string) ([]*dirStat, error) {
   var stats []*dirStat
   index := make(map[string]int)

   err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
      if err != nil {
         log.Printf("%s: %v", path, err)
         if entry != nil && entry.IsDir() {
            return filepath.SkipDir
         }
         return nil
      }

      if entry.IsDir() {
         index[path] = len(stats)
         stats = append(stats, &dirStat{path: path})

         return nil
      }

      if filepath.Ext(path) != ".go" {
         return nil
      }

      i, ok := index[filepath.Dir(path)]
      if !ok {
         return nil
      }

      file, err := scanFile(path)
      if err != nil {
         log.Printf("%s: %v", path, err)
         return nil
      }

      stat := stats[i]
      stat.files++
      stat.loc += file.loc

      if file.pkg == targetPackage {
         stat.mainPkg = true
      }
      if file.imports[targetImport] {
         stat.httpImp = true
      }

      return nil
   })
   if err != nil {
      return nil, err
   }

   return stats, nil
}

// selectRows resolves the display paths, drops every directory that is not a
// target, and sorts largest first.
func selectRows(stats []*dirStat, root string) []*dirStat {
   rows := make([]*dirStat, 0, len(stats))

   for _, s := range stats {
      s.rel = relativePath(root, s.path)

      if !s.isTarget() {
         continue
      }

      rows = append(rows, s)
   }

   slices.SortStableFunc(rows, func(a, b *dirStat) int {
      if n := cmp.Compare(b.loc, a.loc); n != 0 {
         return n
      }

      return cmp.Compare(a.rel, b.rel)
   })

   return rows
}

// isTarget reports whether the directory declares targetPackage and imports
// targetImport in at least one of its own files.
func (d *dirStat) isTarget() bool {
   return d.mainPkg && d.httpImp
}

// goloc.go
