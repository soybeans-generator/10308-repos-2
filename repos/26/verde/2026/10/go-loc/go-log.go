// Command goloc reports, for every directory in a tree, how many lines of Go
// code live *directly* in that directory. Subdirectories are visited, but their
// lines are never rolled up into a parent.
//
// A line is counted only when it holds at least one character that is neither
// whitespace nor part of a comment. Contents of string and rune literals are
// code, so "//" or "/*" inside a literal does not start a comment.
//
// Usage:
//
//   go run goloc.go                 # scan the current directory
//   go run goloc.go D:\code\ambra   # scan an explicit root
//   go run goloc.go -asc -all       # ascending, also list dirs with 0 Go LOC
//   go run goloc.go -notest -top 25 # ignore _test.go, show the top 25
package main

import (
   "bufio"
   "encoding/json"
   "flag"
   "fmt"
   "io"
   "io/fs"
   "os"
   "path/filepath"
   "sort"
   "strings"
)

// countFile returns the number of code lines in the file at path.
func countFile(path string) (int, error) {
   f, err := os.Open(path)
   if err != nil {
      return 0, err
   }
   defer f.Close()
   return countLines(f)
}

// countLines counts lines that contain something other than whitespace and
// comments. It is a small byte-level state machine, so it copes with:
//
//   - // line comments and /* block */ comments spanning any number of lines
//   - trailing comments:   x := 1 // done      -> counted (has code)
//   - code after a block:  /* c */ x := 1      -> counted
//   - comment-only lines:  /* c */             -> not counted
//   - literals:            s := "http://a/*b*/" -> counted, no comment started
//   - raw strings:         `...multi line...`   -> each non-blank line counted
func countLines(r io.Reader) (int, error) {
   const (
      stCode = iota
      stLineComment
      stBlockComment
      stInterp // "..."
      stRaw    // `...`
      stRune   // '...'
   )

   br := bufio.NewReader(r)
   state, lines := stCode, 0
   code := false // does the current line carry any code character?

   flush := func() {
      if code {
         lines++
      }
      code = false
   }

   for {
      c, err := br.ReadByte()
      if err == io.EOF {
         break
      }
      if err != nil {
         return 0, err
      }

      switch state {
      case stCode:
         switch c {
         case '\n':
            flush()
         case ' ', '\t', '\r', '\v', '\f':
            // blank
         case '/':
            next, e := br.Peek(1)
            switch {
            case e == nil && next[0] == '/':
               br.ReadByte()
               state = stLineComment
            case e == nil && next[0] == '*':
               br.ReadByte()
               state = stBlockComment
            default:
               code = true // division or a stray slash: still code
            }
         case '"':
            code = true
            state = stInterp
         case '`':
            code = true
            state = stRaw
         case '\'':
            code = true
            state = stRune
         default:
            code = true
         }

      case stLineComment:
         if c == '\n' {
            state = stCode
            flush()
         }

      case stBlockComment:
         if c == '*' {
            if next, e := br.Peek(1); e == nil && next[0] == '/' {
               br.ReadByte()
               state = stCode
            }
         }
         // comment text never marks a line as code; anything after */ can.

      case stInterp:
         switch c {
         case '\\':
            br.ReadByte() // consume the escaped character
            code = true
         case '"':
            state = stCode
         case '\n': // unterminated literal — recover on the next line
            state = stCode
            flush()
         default:
            code = true
         }

      case stRaw:
         switch c {
         case '`':
            state = stCode
         case '\n':
            flush() // a blank line inside a raw literal is not counted
         case ' ', '\t', '\r':
         default:
            code = true
         }

      case stRune:
         switch c {
         case '\\':
            br.ReadByte()
            code = true
         case '\'':
            state = stCode
         case '\n':
            state = stCode
            flush()
         default:
            code = true
         }
      }
   }

   flush() // last line without a trailing newline
   return lines, nil
}
func fatal(err error) { fmt.Fprintf(os.Stderr, "goloc: %v\n", err); os.Exit(1) }

func main() {
   var (
      asc    = flag.Bool("asc", false, "sort ascending (smallest first) instead of descending")
      all    = flag.Bool("all", false, "also list directories that contain no counted Go code")
      noTest = flag.Bool("notest", false, "skip _test.go files")
      asJSON = flag.Bool("json", false, "write JSON instead of a table")
      top    = flag.Int("top", 0, "print only the first N directories (0 = all)")
      skip   = flag.String("skip", ".git,.hg,.svn,node_modules,vendor",
         "comma separated directory names to prune")
   )
   flag.Usage = func() {
      fmt.Fprintf(os.Stderr, "usage: %s [flags] [root]\n\nflags:\n", filepath.Base(os.Args[0]))
      flag.PrintDefaults()
   }
   flag.Parse()

   root := "."
   if flag.NArg() > 0 {
      root = flag.Arg(0)
   }
   root, err := filepath.Abs(root)
   if err != nil {
      fatal(err)
   }
   if fi, err := os.Stat(root); err != nil {
      fatal(err)
   } else if !fi.IsDir() {
      fatal(fmt.Errorf("%s is not a directory", root))
   }

   prune := map[string]bool{}
   for _, name := range strings.Split(*skip, ",") {
      if name = strings.TrimSpace(name); name != "" {
         prune[name] = true
      }
   }

   var (
      stats []dirStat
      index = map[string]int{} // absolute dir path -> index in stats
   )

   err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
      if err != nil {
         warn(err)
         if d != nil && d.IsDir() {
            return filepath.SkipDir
         }
         return nil
      }

      if d.IsDir() {
         if p != root && prune[d.Name()] {
            return filepath.SkipDir
         }
         index[p] = len(stats)
         stats = append(stats, dirStat{Path: p})
         return nil
      }

      if filepath.Ext(p) != ".go" {
         return nil
      }
      if *noTest && strings.HasSuffix(p, "_test.go") {
         return nil
      }
      i, ok := index[filepath.Dir(p)] // a file always lands in its own dir's bucket
      if !ok {
         return nil
      }

      n, err := countFile(p)
      if err != nil {
         warn(fmt.Errorf("%s: %w", p, err))
         return nil
      }
      stats[i].LOC += n
      stats[i].Files++
      return nil
   })
   if err != nil {
      fatal(err)
   }

   // Pretty paths, relative to the root.
   for i := range stats {
      rel, err := filepath.Rel(root, stats[i].Path)
      if err != nil {
         rel = stats[i].Path
      }
      if rel == "." {
         rel = "." + string(filepath.Separator) // the root itself
      }
      stats[i].Rel = filepath.ToSlash(rel)
   }

   sort.SliceStable(stats, func(a, b int) bool {
      if stats[a].LOC != stats[b].LOC {
         if *asc {
            return stats[a].LOC < stats[b].LOC
         }
         return stats[a].LOC > stats[b].LOC
      }
      return stats[a].Rel < stats[b].Rel // stable tie-break on path
   })

   totalLOC, totalFiles := 0, 0
   for _, s := range stats {
      totalLOC += s.LOC
      totalFiles += s.Files
   }

   shown := stats
   if !*all {
      shown = make([]dirStat, 0, len(stats))
      for _, s := range stats {
         if s.Files > 0 {
            shown = append(shown, s)
         }
      }
   }
   if *top > 0 && *top < len(shown) {
      shown = shown[:*top]
   }

   if *asJSON {
      enc := json.NewEncoder(os.Stdout)
      enc.SetIndent("", "  ")
      if err := enc.Encode(shown); err != nil {
         fatal(err)
      }
      return
   }

   wLOC, wFiles := len(fmt.Sprint(totalLOC)), len(fmt.Sprint(totalFiles))
   for _, s := range shown {
      if n := len(fmt.Sprint(s.LOC)); n > wLOC {
         wLOC = n
      }
      if n := len(fmt.Sprint(s.Files)); n > wFiles {
         wFiles = n
      }
   }
   fmt.Printf("%*s  %*s  %s\n", wLOC, "LOC", wFiles, "FILES", "DIRECTORY")
   for _, s := range shown {
      fmt.Printf("%*d  %*d  %s\n", wLOC, s.LOC, wFiles, s.Files, s.Rel)
   }
   fmt.Printf("%*s  %*s  %s\n", wLOC, strings.Repeat("-", wLOC), wFiles, strings.Repeat("-", wFiles), "")
   fmt.Printf("%*d  %*d  total in %d directories (%d listed, %d skipped with no Go code)\n",
      wLOC, totalLOC, wFiles, totalFiles, len(stats), len(shown), len(stats)-len(shown))
}

func warn(err error) { fmt.Fprintf(os.Stderr, "goloc: warning: %v\n", err) }

// dirStat holds the tally for a single directory (its own files only).
type dirStat struct {
   Path  string `json:"-"`    // absolute
   Rel   string `json:"path"` // relative to the scanned root
   LOC   int    `json:"loc"`
   Files int    `json:"files"`
}
