package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	win := os.Getenv("WINDIR")
	gac := win + "/Microsoft.NET/assembly/GAC_MSIL/System.Runtime"

	var rt string
	err := filepath.Walk(gac, func(p string, info os.FileInfo, err error) error {
		if err == nil {
			if info.Name() == "System.Runtime.dll" {
				rt = p
				return filepath.SkipAll
			}
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}

	cmd := exec.Command(
		win+"/Microsoft.NET/Framework64/v4.0.30319/csc.exe",
		"/r:"+rt,
		"/r:"+win+"/System32/WinMetadata/Windows.Foundation.winmd",
		"/r:"+win+"/System32/WinMetadata/Windows.Media.winmd",
		"PrIndiv.cs",
	)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr

	fmt.Println(cmd.String())
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}
