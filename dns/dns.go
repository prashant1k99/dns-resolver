package dns

import (
	"fmt"
	"net"
	"os"
	"text/tabwriter"
)

func FetchDNS(domainName string, queryType string, verbose bool) {
	requestMessage := []byte{}
	message := prepareMessage(domainName, queryType)

	requestMessage = append(requestMessage, message.Header...)
	requestMessage = append(requestMessage, message.Question...)

	queryURL := "198.41.0.4"
	for {
		msg := queryServer(queryURL, requestMessage, domainName)
		if verbose {
			printResult(msg)
		}

		if msg.Header.ANCOUNT != 0 {
			prityPrintAnswer(msg.Answer)
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

	fmt.Printf("Querying %s for %s\n\n", queryURL, domainName)
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

func printResult(msg DNSMesage) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, ";; DNS Header Section:")
	fmt.Fprintln(w, "ID\tFlags\tQuestion-Count\tAnswer-Count\tAuthority-Count\tAdditional-Count")
	fmt.Fprintf(w, "%d\t%d\t%d\t%d\t%d\t%d\n", msg.Header.ID, msg.Header.Flags, msg.Header.QDCOUNT, msg.Header.ANCOUNT, msg.Header.NSCOUNT, msg.Header.ARCOUNT)
	fmt.Fprintln(w)
	if msg.Header.QDCOUNT > 0 {
		fmt.Fprintln(w, ";; DNS Question Section:")
		fmt.Fprintln(w, "Domain\tType\tClass")
		for _, q := range msg.Question {
			fmt.Fprintf(w, "%s\t%s\t%s\n", q.Name, q.QTYPE, q.QCLASS)
		}
		fmt.Fprintln(w)
	}
	if msg.Header.NSCOUNT > 0 {
		fmt.Fprintln(w, ";; DNS Authoritative Section:")
		fmt.Fprintln(w, "Domain\tType\tClass\tTTL\tDATA")
		for _, an := range msg.Answer {
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n", an.Name, an.ATYPE, an.ACLASS, an.TTL, an.RDATA)
		}
		fmt.Fprintln(w)
	}
	if msg.Header.ARCOUNT > 0 {
		fmt.Fprintln(w, ";; DNS Additional Section:")
		fmt.Fprintln(w, "Domain\tType\tClass\tTTL\tDATA")
		for _, an := range msg.Answer {
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n", an.Name, an.ATYPE, an.ACLASS, an.TTL, an.RDATA)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "==============================================")
	w.Flush()
}

func prityPrintAnswer(answer []DNSRR) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, ";; DNS Answer Section:")
	fmt.Fprintln(w, "Domain\tType\tClass\tTTL\tDATA")
	for _, an := range answer {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n", an.Name, an.ATYPE, an.ACLASS, an.TTL, an.RDATA)
	}
	fmt.Fprintln(w)
	w.Flush()
}
