// steps_other.go begin
//go:build !windows

// The four DLL steps are stubs on a platform that cannot run them. They exist so that main.go
// can name them, and so that `prkf -1` fails with a reason instead of "flag provided but not
// defined". The real ones are in signing.go, warbird.go, nibblemap.go and capture.go, none of
// which is compiled here.

package main

import (
   "fmt"
   "os"
)

// childMode is a stub: there are no children to spawn when the DLL half is not compiled.
func childMode() (bool, error) { return false, nil }

func cmdCapture() int {
   return dllUnavailable("4")
}

func cmdFindSub() error {
   return fmt.Errorf("prkf -1 reads %s: it runs on Windows only",
      "Windows.Media.Protection.PlayReady.dll")
}

func dllUnavailable(step string) int {
   fmt.Fprintf(os.Stderr, "prkf: -%s reads the DLL: it runs on Windows only\n", step)
   return 1
}

func dmDeriveMap() int {
   return dllUnavailable("3")
}

func stageDecryptImg() int {
   return dllUnavailable("2")
}

// steps_other.go end
