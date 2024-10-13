package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
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
	Name   string // Name of the domain
	QTYPE  string // 2byte Type Code
	QCLASS string // 2 byte Class Code
}

type DNSRR struct {
	Name   string
	ATYPE  string // RR Type Code [2 byte]
	ACLASS string // RR Class code | 2 bytes
	TTL    uint32 // Time To Live | 32 bits - 4 bytes
	// RDLENGTH uint16 // Signifies the length of the RDATA in octet meaning bytes
	RDATA string
}

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
		name, newOffset, err := parseDomainName(dnsResponse[offset:], 0)
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

func parseDNSAnswer(dnsResponse []byte, ANCOUNT, offset int) ([]DNSRR, int, error) {
	var answers []DNSRR

	for i := 0; i < ANCOUNT; i++ {
		var name string
		if dnsResponse[offset] == 0xc0 {
			offset++
			newOffset := dnsResponse[offset]
			_name, _, err := parseDomainName(dnsResponse[newOffset:], 0)
			if err != nil {
				fmt.Println("Err:", err)
				return nil, 0, err
			}
			name = _name
			offset++
		} else {
			_name, newOffset, err := parseDomainName(dnsResponse[offset:], 0)
			if err != nil {
				fmt.Println("Err:", err)
				return nil, 0, err
			}
			name = _name
			offset += newOffset
		}
		responseDataLength := binary.BigEndian.Uint16(dnsResponse[offset+8 : offset+10])
		responseType := getTypeString(binary.BigEndian.Uint16(dnsResponse[offset : offset+2]))
		var responseRDATA string
		if responseType == "NS" {
			responseRDATA = generateDomainNameFromBytes(dnsResponse, offset+10, offset+10+int(responseDataLength))
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

func generateDomainNameFromBytes(data []byte, offset, maxIndex int) string {
	return ""
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

	// fmt.Printf("%b \n", data)
	for offset < len(data) {
		nameLength := int(data[offset])
		nameLastIndex := offset + nameLength
		offset++
		if nameLength == 0 {
			break
		}
		if offset+nameLength > len(data) {
			return "", offset, errors.New("invalid dns response, malformed response")
		}
		nameParts = append(nameParts, string(data[offset:nameLastIndex+1]))
		offset += nameLength
	}

	return strings.Join(nameParts, "."), offset, nil
}
