// Command gosort reorders the declarations in Go files into go/doc order
// (imports, blank assertions, consts, vars, funcs, types) and reformats them.
package main

import (
   "bytes"
   "flag"
   "fmt"
   "go/ast"
   "go/doc"
   "go/format"
   "go/parser"
   "go/token"
   "log"
   "os"
   "path/filepath"
   "sort"
   "strings"
)

// allBlank reports whether every named value in specs is the blank identifier.
func allBlank(specs []ast.Spec) bool {
   for _, spec := range specs {
      vs, ok := spec.(*ast.ValueSpec)
      if !ok {
         return false
      }
      for _, n := range vs.Names {
         if n.Name != "_" {
            return false
         }
      }
   }
   return true
}

// computeKeys maps each declaration's start offset to its sort key.
func computeKeys(fset *token.FileSet, f *ast.File, dpkg *doc.Package) map[int]int {
   keys := make(map[int]int, len(f.Decls))
   seq := 0

   add := func(cat int, pos token.Pos) {
      off := fset.Position(pos).Offset
      if _, ok := keys[off]; ok {
         return
      }
      keys[off] = pack(cat, seq)
      seq++
   }

   // 0: imports always come first (go/doc does not report them).
   for _, d := range f.Decls {
      if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.IMPORT {
         add(0, gd.Pos())
      }
   }

   // 2-5: standard go/doc order.
   for _, v := range dpkg.Consts {
      add(2, v.Decl.Pos())
   }
   for _, v := range dpkg.Vars {
      add(3, v.Decl.Pos())
   }
   for _, fn := range dpkg.Funcs {
      add(4, fn.Decl.Pos())
   }
   for _, t := range dpkg.Types {
      add(5, t.Decl.Pos())
      for _, v := range t.Consts {
         add(5, v.Decl.Pos())
      }
      for _, v := range t.Vars {
         add(5, v.Decl.Pos())
      }
      for _, fn := range t.Funcs {
         add(5, fn.Decl.Pos())
      }
      for _, m := range t.Methods {
         add(5, m.Decl.Pos())
      }
   }

   // Whatever go/doc did not report (orphaned methods, receiver types living in
   // another file) gets a category guess and keeps source order.
   for _, d := range f.Decls {
      add(fallbackCat(d), d.Pos())
   }

   return keys
}

// endOfLine returns the offset just past pos, any comment starting on pos's
// line, and the newline that follows.
func endOfLine(fset *token.FileSet, f *ast.File, src []byte, pos token.Pos) int {
   end := fset.Position(pos).Offset
   line := fset.Position(pos).Line
   for _, cg := range f.Comments {
      for _, c := range cg.List {
         if fset.Position(c.Pos()).Line == line {
            if e := fset.Position(c.End()).Offset; e > end {
               end = e
            }
         }
      }
   }
   for end < len(src) && src[end] != '\n' {
      end++
   }
   if end < len(src) {
      end++ // skip the '\n'
   }
   return end
}

// fallbackCat guesses a category for declarations go/doc left unranked.
func fallbackCat(d ast.Decl) int {
   switch d := d.(type) {
   case *ast.GenDecl:
      if d.Tok == token.VAR && allBlank(d.Specs) {
         return 1 // keep `var _ Iface = (*T)(nil)` near the top
      }
      switch d.Tok {
      case token.CONST:
         return 2
      case token.VAR:
         return 3
      case token.TYPE:
         return 5
      }
   case *ast.FuncDecl:
      if d.Recv != nil {
         return 5 // method whose receiver type lives in another file
      }
      return 4
   }
   return 1
}

func main() {
   log.SetFlags(log.Ltime)

   writeFlag := flag.Bool("w", false, "Write result to the source file instead of stdout")
   dirFlag := flag.String("dir", "", "Target directory to process")
   flag.Parse()

   if *dirFlag == "" {
      fmt.Println("Error: -dir flag is required")
      flag.Usage()
      os.Exit(1)
   }

   if err := processDirectory(*dirFlag, *writeFlag); err != nil {
      log.Fatal(err)
   }
}

// pack combines a category with a global sequence number into one sortable int.
// Sequence numbers stay far below 2^20 for any realistic file.
func pack(cat, seq int) int { return cat<<20 | seq }

// processDirectory routes every .go file under targetDir to processFile.
func processDirectory(targetDir string, writeResult bool) error {
   info, err := os.Stat(targetDir)
   if err != nil {
      return fmt.Errorf("error accessing path: %w", err)
   }
   if !info.IsDir() {
      return fmt.Errorf("error: target must be a directory, not a file")
   }

   return filepath.WalkDir(targetDir, func(path string, d os.DirEntry, err error) error {
      if err != nil {
         return err
      }
      if d.IsDir() {
         name := d.Name()
         if path != targetDir && (name == "vendor" || name == "testdata" ||
            strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
            return filepath.SkipDir
         }
         return nil
      }
      if !strings.HasSuffix(path, ".go") {
         return nil
      }
      if err := processFile(path, writeResult); err != nil {
         return fmt.Errorf("error processing %s: %w", path, err)
      }
      return nil
   })
}

// processFile reads, formats, reorders and (optionally) rewrites one file.
func processFile(filename string, writeResult bool) error {
   original, err := os.ReadFile(filename)
   if err != nil {
      return fmt.Errorf("error reading file: %w", err)
   }

   // Format first: one declaration per line keeps the offset math honest.
   src, err := format.Source(original)
   if err != nil {
      return fmt.Errorf("source has syntax errors: %w", err)
   }

   out, err := reorder(filename, src)
   if err != nil {
      return err
   }

   if !writeResult {
      _, err := os.Stdout.Write(out)
      return err
   }

   mode := os.FileMode(0o644)
   if st, err := os.Stat(filename); err == nil {
      mode = st.Mode().Perm()
   }
   if err := os.WriteFile(filename, out, mode); err != nil {
      return fmt.Errorf("error writing file: %w", err)
   }
   fmt.Printf("Reordered and formatted %s successfully.\n", filename)
   return nil
}

// reorder returns src with its declarations sorted into go/doc order.
func reorder(filename string, src []byte) ([]byte, error) {
   // go/doc classifies files by name: anything ending in _test.go is treated as
   // a test file whose declarations are dropped (only Examples survive), which
   // would leave every test declaration unranked. Parsing the same bytes under a
   // plain .go name restores real doc order; byte offsets are unaffected.
   docName := filename
   if base := strings.TrimSuffix(filename, "_test.go"); base != filename {
      docName = base + ".go"
   }

   fset := token.NewFileSet()
   f, err := parser.ParseFile(fset, docName, src, parser.ParseComments)
   if err != nil {
      return nil, fmt.Errorf("error parsing file: %w", err)
   }

   dpkg, err := doc.NewFromFiles(fset, []*ast.File{f}, "", doc.AllDecls|doc.PreserveAST)
   if err != nil {
      return nil, fmt.Errorf("error generating doc package: %w", err)
   }

   keys := computeKeys(fset, f, dpkg)

   head := src[:endOfLine(fset, f, src, f.Name.End())]
   cursor := len(head)
   var blocks []block
   for _, d := range f.Decls {
      end := endOfLine(fset, f, src, d.End())
      if end <= cursor {
         continue
      }
      blocks = append(blocks, block{
         code: src[cursor:end],
         key:  keys[fset.Position(d.Pos()).Offset],
      })
      cursor = end
   }
   tail := src[cursor:]

   // Keys are globally unique, so an unstable sort is enough.
   sort.Slice(blocks, func(i, j int) bool { return blocks[i].key < blocks[j].key })

   var buf bytes.Buffer
   buf.Write(head)
   for _, b := range blocks {
      buf.Write(b.code)
   }
   buf.Write(tail)

   out, err := format.Source(buf.Bytes())
   if err != nil {
      return nil, fmt.Errorf("error formatting reassembled source: %w", err)
   }

   // House style: three spaces per indent level. Drop this line for gofmt output.
   return bytes.ReplaceAll(out, []byte("\t"), []byte("   ")), nil
}

// block is one declaration's source text plus its sort key.
type block struct {
   code []byte
   key  int
}
