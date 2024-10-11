package dns

import (
	"encoding/binary"
	"errors"
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
	return header, 0, nil
}
