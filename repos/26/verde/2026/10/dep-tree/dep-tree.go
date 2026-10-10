// deptree.go
package main

import (
   "bufio"
   "bytes"
   "fmt"
   "os"
   "os/exec"
   "slices"
   "strings"
)

func main() {
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
      line := sc.Text()
      if line == "" {
         continue
      }
      parts := strings.Fields(line)
      if len(parts) != 2 {
         continue
      }
      a, b := parts[0], parts[1]
      if root == "" {
         root = a // first line's left side is the main module
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
         walk(d, depth+1)
      }
      delete(inStack, m)
   }

   walk(root, 0)
}
