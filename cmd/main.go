package main

import (
	"fmt"
	"os"

	"github.com/prashant1k99/dns-resolver/dns"
)

func main() {
	// Generate Question Message with appropriate headers and Question
	args := os.Args
	if len(args) == 0 {
		fmt.Println("Domain name not provided")
		os.Exit(1)
	}

	dns.FetchDNS(args[1])
}
