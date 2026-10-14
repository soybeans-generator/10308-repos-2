package main

import (
   "bufio"
   "bytes"
   "encoding/json"
   "fmt"
   "os"
   "os/exec"
   "slices"
   "strings"
)

func main() {
   // 1. Which requirements are direct?
   var modFile goModFile
   editJSON, err := exec.Command("go", "mod", "edit", "-json").Output()
   if err != nil {
      fmt.Fprintln(os.Stderr, "go mod edit -json failed:", err)
      os.Exit(1)
   }
   if err := json.Unmarshal(editJSON, &modFile); err != nil {
      fmt.Fprintln(os.Stderr, "parsing go.mod JSON:", err)
      os.Exit(1)
   }
   direct := make(map[string]bool)
   for _, r := range modFile.Require {
      if !r.Indirect {
         direct[r.Path] = true
      }
   }

   // 2. Build the graph from `go mod graph`.
   cmd := exec.Command("go", "mod", "graph")
   var stderr bytes.Buffer
   cmd.Stderr = &stderr
   out, err := cmd.Output()
   if err != nil {
      fmt.Fprintln(os.Stderr, "go mod graph failed:", err)
      fmt.Fprintln(os.Stderr, stderr.String())
      os.Exit(1)
   }

   children := map[string][]string{}
   var root string

   sc := bufio.NewScanner(bytes.NewReader(out))
   for sc.Scan() {
      parts := strings.Fields(sc.Text())
      if len(parts) != 2 {
         continue
      }
      a, b := parts[0], parts[1]
      // The main module is the only vertex without a version.
      if root == "" && !strings.Contains(a, "@") {
         root = a
      }
      children[a] = append(children[a], b)
   }

   seen := map[string]bool{}
   inStack := map[string]bool{}

   var walk func(m string, depth int)
   walk = func(m string, depth int) {
      indent := strings.Repeat("  ", depth)
      if inStack[m] {
         fmt.Printf("%s%s (cycle)\n", indent, m)
         return
      }
      if seen[m] {
         return
      }
      seen[m] = true
      inStack[m] = true
      fmt.Println(indent + m)

      deps := children[m]
      slices.Sort(deps)
      for _, d := range deps {
         // Only follow the root's *direct* requirements.
         if depth == 0 {
            path, _, _ := strings.Cut(d, "@")
            if !direct[path] {
               continue
            }
         }
         walk(d, depth+1)
      }
      delete(inStack, m)
   }

   if root == "" {
      fmt.Fprintln(os.Stderr, "could not identify main module")
      os.Exit(1)
   }
   walk(root, 0)
}

type goModFile struct {
   Require []struct {
      Path     string
      Version  string
      Indirect bool
   } `json:"Require"`
}
