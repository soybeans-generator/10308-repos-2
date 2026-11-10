// parser.go marker preserve
package claire

import (
   "fmt"
   "go/ast"
   "go/build"
   "go/doc"
   "go/parser"
   "go/token"
   "log"
   "os"
   "path/filepath"
)

// parseGoFiles parses the buildable, non-test Go files in dir. go/build
// resolves build constraints (//go:build lines, GOOS/GOARCH suffixes, cgo) and
// rejects a directory that holds more than one package name.
func parseGoFiles(fset *token.FileSet, dir string) ([]*ast.File, error) {
   pkg, err := build.ImportDir(dir, 0)
   if err != nil {
      return nil, err
   }
   names := make([]string, 0, len(pkg.GoFiles)+len(pkg.CgoFiles))
   names = append(names, pkg.GoFiles...)
   names = append(names, pkg.CgoFiles...)
   files := make([]*ast.File, 0, len(names))
   for _, name := range names {
      file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ParseComments)
      if err != nil {
         return nil, err
      }
      files = append(files, file)
   }
   return files, nil
}

// PackageDoc holds all the documentation for a single package.
type PackageDoc struct {
   Name           string
   RepositoryUrl  string
   Version        string
   ImportPath     string
   StyleSheetPath string
   Doc            string
   Functions      []FuncDoc
   Types          []TypeDoc
   Variables      []VarDoc
   Constants      []VarDoc
   SubPackages    []PackageLink
}

// ParsePackageDoc parses the Go package in the given directory and returns an initialized PackageDoc.
// It does not populate metadata fields like RepositoryUrl or Version.
func ParsePackageDoc(inputPath string) (*PackageDoc, error) {
   fset := token.NewFileSet()
   files, err := parseGoFiles(fset, inputPath)
   if err != nil {
      return nil, err
   }
   docPkg, err := doc.NewFromFiles(fset, files, "./")
   if err != nil {
      return nil, fmt.Errorf("failed to create doc package: %w", err)
   }
   typeNames := make(map[string]struct{}, len(docPkg.Types))
   for _, t := range docPkg.Types {
      typeNames[t.Name] = struct{}{}
   }

   pkgDoc := &PackageDoc{
      Name: docPkg.Name,
      Doc:  docPkg.Doc,
   }

   // -- Helpers to reduce boilerplate --
   processFuncs := func(funcs []*doc.Func) ([]FuncDoc, error) {
      var docs []FuncDoc
      for _, f := range funcs {
         sig, err := formatAndHighlight(f.Decl, fset, typeNames)
         if err != nil {
            return nil, err
         }
         docs = append(docs, FuncDoc{Name: f.Name, Doc: f.Doc, Signature: sig})
      }
      return docs, nil
   }

   processValues := func(values []*doc.Value) ([]VarDoc, error) {
      var docs []VarDoc
      for _, v := range values {
         def, err := formatAndHighlight(v.Decl, fset, typeNames)
         if err != nil {
            return nil, err
         }
         docs = append(docs, VarDoc{Doc: v.Doc, Definition: def})
      }
      return docs, nil
   }

   // -- Processing --
   if pkgDoc.Functions, err = processFuncs(docPkg.Funcs); err != nil {
      return nil, err
   }

   for _, t := range docPkg.Types {
      def, err := formatAndHighlight(t.Decl, fset, typeNames)
      if err != nil {
         return nil, err
      }
      typeDoc := TypeDoc{Name: t.Name, Doc: t.Doc, Definition: def}

      // Map constants and variables explicitly grouped under this type
      if typeDoc.Constants, err = processValues(t.Consts); err != nil {
         return nil, err
      }
      if typeDoc.Variables, err = processValues(t.Vars); err != nil {
         return nil, err
      }

      if typeDoc.Functions, err = processFuncs(t.Funcs); err != nil {
         return nil, err
      }
      if typeDoc.Methods, err = processFuncs(t.Methods); err != nil {
         return nil, err
      }
      pkgDoc.Types = append(pkgDoc.Types, typeDoc)
   }

   // Map untyped / base-level constants and variables
   if pkgDoc.Constants, err = processValues(docPkg.Consts); err != nil {
      return nil, err
   }
   if pkgDoc.Variables, err = processValues(docPkg.Vars); err != nil {
      return nil, err
   }

   return pkgDoc, nil
}

// IsEmpty reports whether the package documentation is empty (has no content).
func (p *PackageDoc) IsEmpty() bool {
   return p.Doc == "" &&
      len(p.Constants) == 0 &&
      len(p.Variables) == 0 &&
      len(p.Functions) == 0 &&
      len(p.Types) == 0
}

// Render generates the HTML documentation file using the embedded template.
func (p *PackageDoc) Render(outputPath string) error {
   if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
      return err
   }
   log.Printf("Creating file: %s", outputPath)
   file, err := os.Create(outputPath)
   if err != nil {
      return err
   }
   defer file.Close()
   return packageTemplate.Execute(file, p)
}

// parser.go marker preserve
