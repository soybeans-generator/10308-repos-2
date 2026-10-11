// count.go

package main

import (
   "bufio"
   "io"
   "os"
   "strings"
   "unicode"
   "unicode/utf8"
)

// parsePkg returns the identifier that follows the first "package" token in s,
// or an empty string when there is none. s holds code only: comments and
// literal text have already been stripped by scan.
func parsePkg(s string) string {
   isStart := func(r rune) bool {
      return r == '_' || unicode.IsLetter(r)
   }
   isPart := func(r rune) bool {
      return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
   }

   seenPackage := false

   for i := 0; i < len(s); {
      r, size := utf8.DecodeRuneInString(s[i:])
      if !isStart(r) {
         i += size
         continue
      }

      start := i
      for i < len(s) {
         r, size := utf8.DecodeRuneInString(s[i:])
         if !isPart(r) {
            break
         }
         i += size
      }

      token := s[start:i]
      if !seenPackage {
         if token == "package" {
            seenPackage = true
         }
         continue
      }

      return token
   }

   return ""
}

// scan counts lines that contain something other than whitespace and comments,
// and reports the package name. It is a byte-level state machine, so it copes
// with:
//
//   - // line comments and /* block */ comments spanning any number of lines
//   - trailing comments:   x := 1 // done       -> counted, it has code
//   - code after a block:  /* c */ x := 1       -> counted
//   - comment-only lines:  /* c */              -> not counted
//   - literals:            s := "http://a/*b*/" -> counted, no comment started
//   - raw strings:         `...multi line...`   -> each non-blank line counted
//   - build tags:          //go:build linux     -> a comment, not counted
func scan(r io.Reader) (int, string, error) {
   const (
      stCode = iota
      stLineComment
      stBlockComment
      stInterp // "..."
      stRaw    // `...`
      stRune   // '...'
   )

   const maxCapture = 64 << 10 // stop buffering once the clause is nowhere near

   br := bufio.NewReader(r)

   var buf strings.Builder // code bytes seen so far, used to find the clause
   state := stCode
   lines := 0
   code := false // does the current line carry any code character?
   pkg := ""     // found package name, empty until identified

   flush := func() {
      if code {
         lines++
      }
      code = false
   }

   capture := func(b byte) {
      if pkg == "" && buf.Len() < maxCapture {
         buf.WriteByte(b)
      }
   }

   tryPkg := func() {
      if pkg != "" || buf.Len() == 0 {
         return
      }
      if name := parsePkg(buf.String()); name != "" {
         pkg = name
         buf.Reset()
      }
   }

   for {
      c, err := br.ReadByte()
      if err == io.EOF {
         break
      }
      if err != nil {
         return 0, "", err
      }

      switch state {
      case stCode:
         switch c {
         case '\n':
            flush()
            capture(c)
            tryPkg()

         case ' ', '\t', '\r', '\v', '\f':
            capture(c) // a token separator, not code

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
               capture(c)
            }

         case '"':
            code = true
            state = stInterp // literal text is not captured

         case '`':
            code = true
            state = stRaw

         case '\'':
            code = true
            state = stRune

         default:
            code = true
            capture(c)
         }

      case stLineComment:
         if c == '\n' {
            state = stCode
            flush()
            capture(c)
            tryPkg()
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
            br.ReadByte() // consume the escaped character
            code = true
         case '"':
            state = stCode
         case '\n':
            state = stCode // unterminated literal, recover on the next line
            flush()
            capture(c)
            tryPkg()
         default:
            code = true
         }

      case stRaw:
         switch c {
         case '`':
            state = stCode
         case '\n':
            flush() // a blank line inside a raw literal is not counted
            capture(c)
            tryPkg()
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
            capture(c)
            tryPkg()
         default:
            code = true
         }
      }
   }

   flush() // last line without a trailing newline
   tryPkg()

   return lines, pkg, nil
}

// scanFile returns the code-line count and package clause of one file.
func scanFile(path string) (int, string, error) {
   f, err := os.Open(path)
   if err != nil {
      return 0, "", err
   }
   defer f.Close()

   return scan(f)
}

// count.go
