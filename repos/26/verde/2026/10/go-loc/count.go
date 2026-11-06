// count.go

package main

import (
   "bufio"
   "io"
   "os"
   "strings"
)

// declKeyword marks the end of a file's import section: the spec requires every
// import to come before any other declaration.
var declKeyword = map[string]bool{
   "const": true,
   "func":  true,
   "type":  true,
   "var":   true,
}

// isIdentByte reports whether b can be part of a Go identifier. Bytes at or
// above 0x80 are accepted wholesale, which covers the multi-byte letters Go
// allows in identifiers.
func isIdentByte(b byte) bool {
   switch {
   case b >= 0x80:
      return true
   case b == '_':
      return true
   case b >= '0' && b <= '9':
      return true
   case b >= 'a' && b <= 'z':
      return true
   case b >= 'A' && b <= 'Z':
      return true
   }

   return false
}

// fileStat describes one scanned Go file.
type fileStat struct {
   loc     int             // counted code lines
   pkg     string          // package clause, empty when the file has none
   imports map[string]bool // import paths, gathered in the import section only
}

// scan counts lines that contain something other than whitespace and comments,
// and reports the package name and the imported paths. It is a byte-level state
// machine, so it copes with:
//
//   - // line comments and /* block */ comments spanning any number of lines
//   - trailing comments:   x := 1 // done       -> counted, it has code
//   - code after a block:  /* c */ x := 1       -> counted
//   - comment-only lines:  /* c */              -> not counted
//   - literals:            s := "http://a/*b*/" -> counted, no comment started
//   - raw strings:         `...multi line...`   -> each non-blank line counted
//   - build tags:          //go:build linux     -> a comment, not counted
//
// Import paths are the interpreted string literals that appear between the
// package clause and the first const, func, type or var token, so a literal
// later in the file can never be mistaken for an import. Named and blank
// imports record the path, not the local name.
func scan(r io.Reader) (*fileStat, error) {
   const (
      stCode = iota
      stLineComment
      stBlockComment
      stInterp // "..."
      stRaw    // `...`
      stRune   // '...'
   )

   br := bufio.NewReader(r)
   out := &fileStat{
      imports: make(map[string]bool),
   }

   state := stCode
   code := false        // does the current line carry any code character?
   inImports := false   // inside the import section, so literals are paths
   seenPackage := false // the "package" keyword has been passed

   var word strings.Builder // the identifier being read in stCode
   var lit strings.Builder  // the string literal being read while inImports

   flush := func() {
      if code {
         out.loc++
      }
      code = false
   }

   flushWord := func() {
      if word.Len() == 0 {
         return
      }

      token := word.String()
      word.Reset()

      if !seenPackage {
         if token == "package" {
            seenPackage = true
         }
         return
      }

      if out.pkg == "" {
         out.pkg = token
         inImports = true
         return
      }

      if declKeyword[token] {
         inImports = false
      }
   }

   for {
      c, err := br.ReadByte()
      if err == io.EOF {
         break
      }
      if err != nil {
         return nil, err
      }

      switch state {
      case stCode:
         if isIdentByte(c) {
            word.WriteByte(c)
            code = true
            continue
         }

         flushWord()

         switch c {
         case '\n':
            flush()

         case ' ', '\t', '\r', '\v', '\f':
            // whitespace

         case '/':
            next, peekErr := br.Peek(1)
            switch {
            case peekErr == nil && next[0] == '/':
               br.ReadByte()
               state = stLineComment
            case peekErr == nil && next[0] == '*':
               br.ReadByte()
               state = stBlockComment
            default:
               code = true // division or a stray slash is still code
            }

         case '"':
            code = true
            lit.Reset()
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
            next, peekErr := br.Peek(1)
            if peekErr == nil && next[0] == '/' {
               br.ReadByte()
               state = stCode
            }
         }
         // Comment text never marks a line as code; anything after */ can.

      case stInterp:
         switch c {
         case '\\':
            next, readErr := br.ReadByte()
            if readErr == nil {
               lit.WriteByte(c)
               lit.WriteByte(next)
            }
            code = true
         case '"':
            if inImports {
               out.imports[lit.String()] = true
               lit.Reset()
            }
            state = stCode
         case '\n':
            state = stCode // unterminated literal, recover on the next line
            lit.Reset()
            flush()
         default:
            if inImports {
               lit.WriteByte(c)
            }
            code = true
         }

      case stRaw:
         switch c {
         case '`':
            state = stCode
         case '\n':
            flush() // a blank line inside a raw literal is not counted
         case ' ', '\t', '\r':
            // whitespace inside a raw literal
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

   flush()     // last line without a trailing newline
   flushWord() // identifier still open at EOF

   return out, nil
}

// scanFile reads the file at path and reports its code lines, package clause
// and import paths.
func scanFile(path string) (*fileStat, error) {
   f, err := os.Open(path)
   if err != nil {
      return nil, err
   }
   defer f.Close()

   return scan(f)
}

// count.go
