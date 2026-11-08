package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	win := os.Getenv("WINDIR")
	matches, err := filepath.Glob(win + "/Microsoft.NET/assembly/GAC_MSIL/System.Runtime/*/System.Runtime.dll")
	if err != nil {
		log.Fatal(err)
	}

	csc := exec.Command(
		win+"/Microsoft.NET/Framework64/v4.0.30319/csc.exe",
		"/r:"+matches[0],
		"/r:"+win+"/System32/WinMetadata/Windows.Foundation.winmd",
		"/r:"+win+"/System32/WinMetadata/Windows.Media.winmd",
		"/r:"+win+"/System32/WinMetadata/Windows.Storage.winmd",
		"/r:"+win+"/System32/WinMetadata/Windows.Management.winmd",
		"/r:"+win+"/System32/WinMetadata/Windows.ApplicationModel.winmd",
		"PrIndiv.cs",
	)
	csc.Stdout, csc.Stderr = os.Stdout, os.Stderr
	if err := csc.Run(); err != nil {
		log.Fatal(err)
	}
}
