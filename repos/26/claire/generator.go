// generator.go marker preserve
package claire

import (
   _ "embed"
   "errors"
   "fmt"
   "go/build"
   "html/template"
   "io/fs"
   "log"
   "os"
   "path"
   "path/filepath"
   "slices"
   "strings"
)

var packageTemplate = template.Must(template.New("package").Parse(packageTemplateFile))

//go:embed package.tmpl
var packageTemplateFile string

//go:embed style.css
var styleFile string

// Generate creates HTML documentation for all packages within a Go module.
func Generate(sourceDir, outputDir, repoUrl, version, importPath string) error {
   if err := os.MkdirAll(outputDir, 0o755); err != nil {
      return err
   }
   cssDestPath := filepath.Join(outputDir, "style.css")
   log.Printf("Creating file: %s", cssDestPath)
   if err := os.WriteFile(cssDestPath, []byte(styleFile), 0o644); err != nil {
      return err
   }
   styleSheetPath := calculateStyleSheetPath(importPath)

   pkgDirs, err := findAllPackageDirs(sourceDir)
   if err != nil {
      return err
   }

   // Parse every package. A package with no exported documentation is not
   // documentable: it gets no page and no link.
   pkgDocs := make(map[string]*PackageDoc, len(pkgDirs))
   for _, d := range pkgDirs {
      fullPath := filepath.Join(sourceDir, d)
      pd, err := ParsePackageDoc(fullPath)
      if err != nil {
         return fmt.Errorf("parsing package in %s: %w", fullPath, err)
      }
      if pd.IsEmpty() {
         log.Printf("skipping package %q: no exported documentation", d)
         continue
      }
      pkgDocs[d] = pd
   }

   // A directory needs a page if it is the root, if it holds documented
   // declarations, or if it is an ancestor of a directory that does.
   dirSet := map[string]struct{}{".": {}}
   for p := range pkgDocs {
      for d := p; d != "."; d = filepath.Dir(d) {
         dirSet[d] = struct{}{}
      }
   }
   dirs := make([]string, 0, len(dirSet))
   for d := range dirSet {
      dirs = append(dirs, d)
   }
   slices.Sort(dirs) // parents sort before children: "." < "provider" < "provider/amazon"

   // Build all docs first, render afterwards, so SubPackages is complete.
   docs := make(map[string]*PackageDoc, len(dirs))
   for _, d := range dirs {
      pd, ok := pkgDocs[d]
      if !ok {
         log.Printf("directory %q has no documented declarations; emitting container page", d)
         pd = &PackageDoc{Name: filepath.Base(d)}
         if d == "." {
            pd.Name = filepath.Base(importPath)
         }
      }
      pd.RepositoryUrl = repoUrl
      pd.Version = version
      pd.StyleSheetPath = styleSheetPath
      pd.ImportPath = path.Join(importPath, filepath.ToSlash(d))
      docs[d] = pd
   }

   // Each directory lists its immediate children. Href is relative to the
   // linking page; Path is what gets displayed.
   link := func(from, to string) PackageLink {
      rel, _ := filepath.Rel(from, to) // both live under the same root
      return PackageLink{
         Path: filepath.ToSlash(to),
         Href: filepath.ToSlash(rel) + "/",
      }
   }
   children := make(map[string][]string, len(dirs))
   for _, d := range dirs {
      if d == "." {
         continue
      }
      parent := filepath.Dir(d)
      children[parent] = append(children[parent], d)
   }
   for _, d := range dirs {
      for _, child := range children[d] {
         docs[d].SubPackages = append(docs[d].SubPackages, link(d, child))
      }
   }

   for _, d := range dirs {
      if err := docs[d].Render(filepath.Join(outputDir, d, "index.html")); err != nil {
         return err
      }
   }
   return nil
}

func calculateStyleSheetPath(importPath string) string {
   var pathPrefix string
   if parts := strings.SplitN(importPath, "/", 2); len(parts) > 1 {
      pathPrefix = parts[1]
   }
   return path.Join("/", pathPrefix, "style.css")
}

// findAllPackageDirs returns the module-relative directories holding buildable
// Go code. go/build decides what counts, so build-constrained, cgo-less and
// test-only directories are skipped instead of aborting the run.
func findAllPackageDirs(root string) ([]string, error) {
   var packages []string
   err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
      if err != nil {
         return err
      }
      if !d.IsDir() {
         return nil
      }
      if p != root && (d.Name() == "vendor" || d.Name() == "testdata") {
         return filepath.SkipDir
      }
      if _, err := build.ImportDir(p, 0); err != nil {
         var noGo *build.NoGoError
         if !errors.As(err, &noGo) {
            return err
         }
         return nil
      }
      rel, err := filepath.Rel(root, p)
      if err != nil {
         return err
      }
      packages = append(packages, rel)
      return nil
   })
   return packages, err
}

// FuncDoc holds documentation for a single function or method.
type FuncDoc struct {
   Name      string
   Doc       string
   Signature template.HTML
}

// PackageLink is one entry in a "Packages" list. Path is the import-relative
// path shown to the reader; Href is relative to the page that renders the
// list, so the same list works at any depth.
type PackageLink struct {
   Path string
   Href string
}

// TypeDoc holds documentation for a type definition and its methods.
type TypeDoc struct {
   Constants  []VarDoc // Constants grouped under this type
   Definition template.HTML
   Doc        string
   Functions  []FuncDoc // Constructors/factory functions associated with this type.
   Methods    []FuncDoc
   Name       string
   Variables  []VarDoc // Variables grouped under this type
}

// VarDoc holds documentation for a variable or constant declaration.
type VarDoc struct {
   Doc        string
   Definition template.HTML
}

// generator.go marker preserve
