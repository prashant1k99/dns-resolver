package main

import (
	"fmt"
	"os"
)

func main() {
	// Generate Question Message with appropriate headers and Question
	args := os.Args
	fmt.Println("args:", args)
	if len(args) == 0 {
		fmt.Println("Domain name not provided")
		os.Exit(1)
	}

	fmt.Println("domain:", args[1])
}
