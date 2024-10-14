package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func parseDNSFlags(flags uint16) DNSFlags {
	return DNSFlags{
		QR:     uint8((flags >> 15) & 0x1),
		OPCODE: uint8((flags >> 11) & 0xF),
		AA:     uint8((flags >> 10) & 0x1),
		TC:     uint8((flags >> 9) & 0x1),
		RD:     uint8((flags >> 8) & 0x1),
		RA:     uint8((flags >> 7) & 0x1),
		Z:      uint8((flags >> 4) & 0x7),
		RCODE:  uint8(flags & 0xF),
	}
}

func parseDNSHeader(dnsResponse []byte) (*DNSHeader, int, error) {
	if len(dnsResponse) < 12 {
		return nil, 0, errors.New("invalid dns response")
	}
	header := &DNSHeader{
		ID:      binary.BigEndian.Uint16(dnsResponse[:2]),
		Flags:   parseDNSFlags(binary.BigEndian.Uint16(dnsResponse[2:4])),
		QDCOUNT: binary.BigEndian.Uint16(dnsResponse[4:6]),
		ANCOUNT: binary.BigEndian.Uint16(dnsResponse[6:8]),
		NSCOUNT: binary.BigEndian.Uint16(dnsResponse[8:10]),
		ARCOUNT: binary.BigEndian.Uint16(dnsResponse[10:]),
	}
	return header, 12, nil
}

func parseDNSQuestion(dnsResponse []byte, QDCOUNT, offset int) ([]DNSQuestion, int, error) {
	var questions []DNSQuestion

	for i := 0; i < QDCOUNT; i++ {
		name, newOffset, err := parseDomainName(dnsResponse, offset)
		fmt.Println(newOffset)
		if err != nil {
			fmt.Println("Err:", err)
			return nil, 0, err
		}

		offset += newOffset
		questions = append(questions, DNSQuestion{
			Name:   name,
			QTYPE:  getTypeString(binary.BigEndian.Uint16(dnsResponse[offset : offset+2])),
			QCLASS: getClassString(binary.BigEndian.Uint16(dnsResponse[offset+2 : offset+4])),
		})
		offset += 4
	}

	return questions, offset, nil
}

func parseDNSAnswer(dnsResponse []byte, COUNT, offset int) ([]DNSRR, int, error) {
	var answers []DNSRR

	for i := 0; i < COUNT; i++ {
		name, newOffset, err := parseDomainName(dnsResponse[offset:], 0)
		if err != nil {
			fmt.Println("Err:", err)
			return nil, 0, err
		}
		offset += newOffset

		responseDataLength := binary.BigEndian.Uint16(dnsResponse[offset+8 : offset+10])

		responseType := getTypeString(binary.BigEndian.Uint16(dnsResponse[offset : offset+2]))

		var responseRDATA string
		if responseType == "NS" {
			res, _, err := parseDomainName(dnsResponse, offset+10)
			if err != nil {
				fmt.Println("Err:", err)
				os.Exit(1)
			}
			responseRDATA = res
		} else {
			responseRDATA = generateIpFromBytes(dnsResponse[offset+10:offset+10+int(responseDataLength)], responseType)
		}

		answers = append(answers, DNSRR{
			Name:   name,
			ATYPE:  responseType,
			ACLASS: getClassString(binary.BigEndian.Uint16(dnsResponse[offset+2 : offset+4])),
			TTL:    binary.BigEndian.Uint32(dnsResponse[offset+4 : offset+8]),
			RDATA:  responseRDATA,
		})
		offset += 10 + int(responseDataLength)
	}

	return answers, offset, nil
}

func generateIpFromBytes(data []byte, responseType string) string {
	if responseType == "A" && len(data) == 4 {
		// Handle IPv4
		var ipPart []string
		for _, b := range data {
			ipPart = append(ipPart, strconv.Itoa(int(b)))
		}
		return strings.Join(ipPart, ".")
	} else if responseType == "AAAA" && len(data) == 16 {
		// Handle IPv6
		var ipPart []string
		for i := 0; i < len(data); i += 2 {
			ipPart = append(ipPart, fmt.Sprintf("%02x%02x", data[i], data[i+1]))
		}
		return strings.Join(ipPart, ":")
	}
	return ""
}

func parseDomainName(data []byte, offset int) (string, int, error) {
	var nameParts []string
	isInPointerRef := false
	internalOffset := offset

	for {
		// Check if the value is equal to 0xc0
		fmt.Println(isInPointerRef)
		if data[offset] == 0xc0 {
			isInPointerRef = true
			offset++
			internalOffset = int(data[offset])
			offset++
			continue
		}
		nameLength := int(data[internalOffset])
		internalOffset++
		nameLastIndex := internalOffset + nameLength
		if nameLength == 0 {
			break
		}
		nameParts = append(nameParts, string(data[internalOffset:nameLastIndex+1]))
		if !isInPointerRef {
			offset += nameLength + 1
		}
		internalOffset += nameLength
	}

	return strings.Join(nameParts, "."), offset, nil
}
