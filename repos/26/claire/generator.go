package claire

import (
   _ "embed"
   "html/template"
   "io/fs"
   "log"
   "os"
   "path"
   "path/filepath"
   "slices"
   "strings"
)

//go:embed package.tmpl
var packageTemplateFile string

//go:embed style.css
var styleFile string

// types.go
// Generate creates HTML documentation for all packages within a Go module
func Generate(sourceDir, outputDir, repoUrl, version, importPath string) error {
   if err := os.MkdirAll(outputDir, 0o755); err != nil {
      return err
   }
   cssDestPath := filepath.Join(outputDir, "style.css")
   log.Printf("Creating file: %s", cssDestPath)
   err := os.WriteFile(cssDestPath, []byte(styleFile), 0o644)
   if err != nil {
      return err
   }
   styleSheetPath := calculateStyleSheetPath(importPath)
   allPackagePaths, err := findAllPackageDirs(sourceDir)
   if err != nil {
      return err
   }
   var rootPackageExists bool
   var subPackagePaths []string
   for _, p := range allPackagePaths {
      if p == "." {
         rootPackageExists = true
      } else {
         subPackagePaths = append(subPackagePaths, p)
      }
   }
   slices.Sort(subPackagePaths)
   var subPackages []string
   for _, pkgPath := range subPackagePaths {
      fullPath := filepath.Join(sourceDir, pkgPath)
      pkgOutputDir := filepath.Join(outputDir, pkgPath)
      // Parse the package without metadata first.
      pkgDoc, err := ParsePackageDoc(fullPath)
      if err != nil {
         log.Printf("Skipping directory %s: %v", fullPath, err)
         continue
      }
      if pkgDoc.IsEmpty() {
         log.Printf("Skipping empty package: %s", fullPath)
         continue
      }
      // Inject metadata.
      pkgDoc.RepositoryUrl = repoUrl
      pkgDoc.Version = version
      pkgDoc.StyleSheetPath = styleSheetPath
      pkgDoc.ImportPath = path.Join(importPath, filepath.ToSlash(pkgPath))
      htmlOutputPath := filepath.Join(pkgOutputDir, "index.html")
      if err := pkgDoc.Render(htmlOutputPath); err != nil {
         return err
      }
      subPackages = append(subPackages, filepath.ToSlash(pkgPath))
   }
   var rootDoc *PackageDoc
   if rootPackageExists {
      rootDoc, err = ParsePackageDoc(sourceDir)
      if err != nil {
         return err
      }
   } else {
      rootDoc = &PackageDoc{Name: filepath.Base(importPath)}
   }
   // Inject metadata for the root package.
   rootDoc.RepositoryUrl = repoUrl
   rootDoc.Version = version
   rootDoc.ImportPath = importPath
   rootDoc.StyleSheetPath = styleSheetPath
   rootDoc.SubPackages = subPackages
   indexPath := filepath.Join(outputDir, "index.html")
   return rootDoc.Render(indexPath)
}

func calculateStyleSheetPath(importPath string) string {
   var pathPrefix string
   if parts := strings.SplitN(importPath, "/", 2); len(parts) > 1 {
      pathPrefix = parts[1]
   }
   return path.Join("/", pathPrefix, "style.css")
}

func findAllPackageDirs(root string) ([]string, error) {
   packageSet := make(map[string]struct{})

   err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
      if err != nil {
         return err
      }

      if d.IsDir() {
         if path != root && d.Name() == "vendor" {
            return filepath.SkipDir
         }
         return nil
      }

      name := d.Name()
      if strings.HasSuffix(name, ".go") &&
         !strings.HasSuffix(name, "_test.go") {
         dir := filepath.Dir(path)
         relDir, err := filepath.Rel(root, dir)
         if err != nil {
            return err
         }
         packageSet[relDir] = struct{}{}
      }

      return nil
   })

   packages := make([]string, 0, len(packageSet))
   for pkg := range packageSet {
      packages = append(packages, pkg)
   }

   return packages, err
}

// FuncDoc holds documentation for a single function or method.
type FuncDoc struct {
   Name      string
   Doc       string
   Signature template.HTML
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

// generator.go
