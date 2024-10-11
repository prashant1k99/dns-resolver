package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

type DNSHeader struct {
	ID      uint16
	Flags   DNSFlags
	QDCOUNT uint16
	ANCOUNT uint16
	NSCOUNT uint16
	ARCOUNT uint16
}

type DNSFlags struct {
	QR     uint8
	OPCODE uint8
	AA     uint8
	TC     uint8
	RD     uint8
	RA     uint8
	Z      uint8
	RCODE  uint8
}

type DNSQuestion struct {
	Name   string
	QTYPE  uint16
	QCLASS uint16
}

func ParseDNSFlags(flags uint16) DNSFlags {
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

func ParseDNSHeader(dnsResponse []byte) (*DNSHeader, int, error) {
	if len(dnsResponse) < 12 {
		return nil, 0, errors.New("invalid dns response")
	}
	header := &DNSHeader{
		ID:      binary.BigEndian.Uint16(dnsResponse[:2]),
		Flags:   ParseDNSFlags(binary.BigEndian.Uint16(dnsResponse[2:4])),
		QDCOUNT: binary.BigEndian.Uint16(dnsResponse[4:6]),
		ANCOUNT: binary.BigEndian.Uint16(dnsResponse[6:8]),
		NSCOUNT: binary.BigEndian.Uint16(dnsResponse[8:10]),
		ARCOUNT: binary.BigEndian.Uint16(dnsResponse[10:]),
	}
	return header, 12, nil
}

func ParseDNSQuestion(dnsResponse []byte, QDCOUNT, offset int) ([]DNSQuestion, int, error) {
	var questions []DNSQuestion

	for i := 0; i < QDCOUNT; i++ {
		name, newOffset, err := parseDomainName(dnsResponse[offset:], 0)
		if err != nil {
			fmt.Println("Err:", err)
			return nil, 0, err
		}
		offset += newOffset
		questions = append(questions, DNSQuestion{
			Name:   name,
			QTYPE:  binary.BigEndian.Uint16(dnsResponse[offset : offset+2]),
			QCLASS: binary.BigEndian.Uint16(dnsResponse[offset+2 : offset+4]),
		})
		offset += 4
	}

	return questions, offset, nil
}

func parseDomainName(data []byte, offset int) (string, int, error) {
	var nameParts []string

	for offset < len(data) {
		nameLength := int(data[offset])
		nameLastIndex := offset + nameLength
		offset++
		if nameLength == 0 {
			break
		}
		if offset+nameLength > len(data) {
			return "", offset, errors.New("invalid dns response, malformed question")
		}
		nameParts = append(nameParts, string(data[offset:nameLastIndex+1]))
		offset += nameLength
	}

	return strings.Join(nameParts, "."), offset, nil
}
