package dns

import (
	"fmt"
	"net"
	"os"
)

func FetchDNS(domainName string, queryType string, verbose bool) {
	requestMessage := []byte{}
	message := prepareMessage(domainName, queryType)

	requestMessage = append(requestMessage, message.Header...)
	requestMessage = append(requestMessage, message.Question...)

	queryURL := "198.41.0.4"
	for {
		msg := queryServer(queryURL, requestMessage, domainName)
		// Print the message
		if msg.Header.ANCOUNT != 0 {
			fmt.Println("URL:", msg.Answer)
			break
		} else {
			for _, record := range msg.Additional {
				if record.ATYPE == "A" {
					queryURL = record.RDATA
					break
				}
			}
		}
	}
}

func queryServer(queryURL string, message []byte, domainName string) DNSMesage {
	msg := DNSMesage{}

	fmt.Printf("Querying %s for %s\n", queryURL, domainName)
	queryURL += ":53"
	serverAddr, err := net.ResolveUDPAddr("udp", queryURL)
	if err != nil {
		fmt.Println("Error resolving address:", err)
		os.Exit(1)
	}

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		fmt.Printf("Error dialing UDP: %v \n", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Send data to the server
	_, err = conn.Write(message)
	if err != nil {
		fmt.Printf("Error sending request: %v \n", err)
		os.Exit(1)
	}

	// Receive requestMessage from the server
	buffer := make([]byte, 512)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		fmt.Printf("Error receiving query response: %v \n", err)
		os.Exit(1)
	}

	offset := 0
	header, newOffset, err := parseDNSHeader(buffer[:n])
	if err != nil {
		fmt.Printf("Error parsing response header: %v \n", err)
		os.Exit(1)
	}
	offset = newOffset
	msg.Header = *header

	// Check for the question count
	if header.QDCOUNT > 0 {
		que, newOffset, err := parseDNSQuestion(buffer[:n], int(header.QDCOUNT), offset)
		if err != nil {
			fmt.Printf("Error parsing response question section: %v \n", err)
			os.Exit(1)
		}
		offset = newOffset
		msg.Question = que
	}

	// Check for Answer Count
	if header.ANCOUNT > 0 {
		ans, newOffset, err := parseDNSAnswer(buffer[:n], int(header.ANCOUNT), offset)
		if err != nil {
			fmt.Printf("Error while parsing response answer: %v \n", err)
			os.Exit(1)
		}
		offset += newOffset
		msg.Answer = ans
	} else if header.NSCOUNT > 0 {
		// this means the answer count is zero and we want to check for NS Count
		authoritative, newOffset, err := parseDNSAnswer(buffer[:n], int(header.NSCOUNT), offset)
		if err != nil {
			fmt.Printf("Error while parsing authoritative section: %v \n", err)
			os.Exit(1)
		}
		offset = newOffset
		msg.Authoritative = authoritative

		additional, newOffset, err := parseDNSAnswer(buffer[:n], int(header.ARCOUNT), offset)
		if err != nil {
			fmt.Printf("Error while parsing Additional section: %v \n", err)
			os.Exit(1)
		}
		offset = newOffset
		msg.Additional = additional
	}

	return msg
}
