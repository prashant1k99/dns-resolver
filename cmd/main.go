package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/prashant1k99/dns-resolver/dns"
)

func main() {
	// Check if there's at least one argument (the string argument)
	if len(os.Args) < 2 {
		fmt.Println("Error: String argument is required")
		fmt.Println("Usage: program <string_argument> -typeFlagPtr value1 -verboseFlagPtr value2")
		os.Exit(1)
	}

	// Get the string argument (first command-line argument after program name)
	domainName := os.Args[1]

	// Remove the program name and string argument from os.Args
	os.Args = append(os.Args[:1], os.Args[2:]...)

	// Define flags
	typeFlagPtr := flag.String("type", "A", "Set the record type to query for domain name")
	flag.StringVar(typeFlagPtr, "t", "A", "Shorthand for type flag")
	verboseFlagPtr := flag.Bool("verbose", false, "Set the verbose flag which is boolean")
	flag.BoolVar(verboseFlagPtr, "v", false, "Shorthand for verbose flag")

	// Parse flags
	flag.Parse()

	// Fetch DNS records
	dns.FetchDNS(domainName, *typeFlagPtr, *verboseFlagPtr)
}
