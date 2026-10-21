// main.go
package main

import (
	"log"
	"os"
)

func main() {
	username, password := os.Getenv("CRITERION_USERNAME"), os.Getenv("CRITERION_PASSWORD")
	if len(os.Args) == 3 {
		username, password = os.Args[1], os.Args[2]
	}
	if username == "" || password == "" {
		log.Fatal("usage: go run . <email> <password>  (or set CRITERION_USERNAME / CRITERION_PASSWORD)")
	}

	f := NewFlow(username, password)
	steps := []struct {
		name string
		run  func() error
	}{
		{"01 login redirect", f.Request01LoginRedirect},
		{"02 authorize", f.Request02Authorize},
		{"03 post identifier", f.Request03PostIdentifier},
		{"04 post password", f.Request04PostPassword},
		{"05 resume to prompt", f.Request05ResumeToPrompt},
		{"06 forms config", f.Request06FormsConfig},
		{"07 forms start", f.Request07FormsStart},
		{"08 forms submission", f.Request08FormsSubmission},
		{"09 post prompt", f.Request09PostPrompt},
		{"10 final resume", f.Request10FinalResume},
		{"11 callback", f.Request11Callback},
	}
	for _, s := range steps {
		if err := s.run(); err != nil {
			log.Fatalf("%s: %v", s.name, err)
		}
		log.Printf("%-22s ok", s.name)
	}
	log.Println("login complete - __session cookie is in the jar")
}
// main.go
