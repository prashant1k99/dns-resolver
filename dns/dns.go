package dns

import (
	"fmt"
	"net"
	"os"
)

func FetchDNS(domainName string) {
	requestMessage := []byte{}
	message := prepareMessage(domainName)

	requestMessage = append(requestMessage, message.Header...)
	requestMessage = append(requestMessage, message.Question...)

	queryServer("198.41.0.4", requestMessage, domainName)
}

func queryServer(url string, message []byte, domainName string) {
	fmt.Printf("Querying %s for %s\n", url, domainName)
	url += ":53"
	serverAddr, err := net.ResolveUDPAddr("udp", url)
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
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		fmt.Println("Error receiving data:", err)
		os.Exit(1)
	}

	offset := 0
	header, _, err := parseDNSHeader(buffer[:n])
	if err != nil {
		fmt.Println("Error while parsing response header:", err)
		os.Exit(1)
	}
	fmt.Println(header)

	// Check for the question count
	offset += 12
	if header.QDCOUNT > 0 {
		que, newOffset, err := parseDNSQuestion(buffer[:n], int(header.QDCOUNT), offset)
		if err != nil {
			fmt.Printf("Error while parsing response header: %v", err)
			os.Exit(1)
		}
		offset = newOffset
		for _, q := range que {
			fmt.Println(q)
		}
	}

	// Check for Answer Count
	if header.ANCOUNT > 0 {
		ans, newOffset, err := parseDNSAnswer(buffer[:n], int(header.ANCOUNT), offset)
		if err != nil {
			fmt.Printf("Error while parsing response answer: %v", err)
			os.Exit(1)
		}
		offset += newOffset
		for _, a := range ans {
			fmt.Println(a)
		}
	} else if header.NSCOUNT > 0 {
		// this means the answer count is zero and we want to check for NS Count
		fmt.Println("Need to parse Authoritative Section and additional section")
		authoritative, newOffset, err := parseDNSAnswer(buffer[:n], int(header.NSCOUNT), offset)
		if err != nil {
			fmt.Printf("Error while parsing authoritative section: %v", err)
			os.Exit(1)
		}
		offset += newOffset
		for _, aa := range authoritative {
			fmt.Println(aa)
		}
	}
}
