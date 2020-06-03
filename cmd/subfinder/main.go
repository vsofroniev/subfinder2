package main

import (
    "log"
    "strings"
	"github.com/projectdiscovery/gologger"
	"github.com/vsofroniev/subfinder2/pkg/runner"
)

func main() {
	// Parse the command line flags and read config files
	options := runner.ParseOptions()

	runner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatalf("Could not create runner: %s\n", err)
	}

    ch, _ := runner.RunEnumeration()
	uniqueMap := make(map[string]struct{})
    for result := range ch{
		subdomain := strings.ReplaceAll(strings.ToLower(result.Value), "*.", "")
	    if _, ok := uniqueMap[subdomain]; ok {
		    continue
		}
		uniqueMap[subdomain] = struct{}{}
    }

	for result := range uniqueMap {
		log.Println(result)
	}
	if err != nil {
		gologger.Fatalf("Could not run enumeration: %s\n", err)
	}
}
