package main

import (
	"fmt"
	"net"
	"os"

	"github.com/prashant1k99/dns-resolver/dns"
)

func QueryServer(message []byte) {
	serverAddr, err := net.ResolveUDPAddr("udp", "8.8.8.8:53")
	if err != nil {
		fmt.Println("Error resolving address:", err)
		os.Exit(1)
	}

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		fmt.Println("Error dialing UDP:", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Send data to the server
	_, err = conn.Write(message)
	if err != nil {
		fmt.Println("Error sending data:", err)
		os.Exit(1)
	}

	// Receive requestMessage from the server
	buffer := make([]byte, 512)
	// n, addr, err := conn.ReadFromUDP(buffer)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		fmt.Println("Error receiving data:", err)
		os.Exit(1)
	}

	fmt.Printf("%8x\n", buffer[:n])

	offset := 0
	header, _, err := dns.ParseDNSHeader(buffer[:n])
	if err != nil {
		fmt.Println("Error while parsing response header:", err)
		os.Exit(1)
	}
	offset += 12
	if header.QDCOUNT > 0 {
		que, newOffset, err := dns.ParseDNSQuestion(buffer[:n], int(header.QDCOUNT), offset)
		if err != nil {
			fmt.Printf("Error while parsing response header: %v", err)
			os.Exit(1)
		}
		offset = newOffset
		for _, q := range que {
			fmt.Println(q)
		}
	}

	if header.ANCOUNT > 0 {
		ans, newOffset, err := dns.ParseDNSAnswer(buffer[:n], int(header.ANCOUNT), offset)
		if err != nil {
			fmt.Printf("Error while parsing response answer: %v", err)
			os.Exit(1)
		}
		offset += newOffset
		for _, a := range ans {
			fmt.Println(a)
		}
	}
}

func main() {
	// Generate Question Message with appropriate headers and Question
	args := os.Args
	if len(args) == 0 {
		fmt.Println("Domain name not provided")
		os.Exit(1)
	}

	requestMessage := []byte{}
	message := dns.PrepareMessage(args[1])

	requestMessage = append(requestMessage, message.Header...)
	requestMessage = append(requestMessage, message.Question...)

	QueryServer(requestMessage)
}
