package dns

import (
	"encoding/binary"
	"math/rand"
	"strings"
	"time"
)

type Message struct {
	Header   []byte
	Question []byte
}

func newMessage() *Message {
	return &Message{
		Header:   make([]byte, 12),
		Question: []byte{},
	}
}

func (m *Message) setHeader(qCount uint16) {
	//  Handle different record query
	binary.BigEndian.PutUint16((*m).Header[0:2], generateId())                         // set Packet Identifier (ID)
	binary.BigEndian.PutUint16((*m).Header[2:4], combineFlags(0, 0, 0, 0, 1, 0, 0, 0)) // set Query/Response Indicator (QR)
	binary.BigEndian.PutUint16((*m).Header[4:6], qCount)                               // set QDCOUNT to 1 to donate that message contains 1 question
}

func (m *Message) setQuestion(domainName string, queryTypes []uint16) {
	for _, queryType := range queryTypes {
		var question []byte
		// if i == 0 {
		// } else {
		// 	question = []byte{0xc0, 0x0c}
		// }

		question = encodeDomain(domainName)
		question = binary.BigEndian.AppendUint16(question, queryType) // Set the type of Query 1 for A record and 5 for CNAME [https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2]
		question = binary.BigEndian.AppendUint16(question, 1)         // Set the Class of Query [https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4]
		(*m).Question = append((*m).Question, question...)

	}
}

func prepareMessage(domainName string, queryType string) *Message {
	queryTypes := strings.Split(queryType, ",")
	var parseQueryTypes []uint16
	for _, b := range queryTypes {
		parseQueryTypes = append(parseQueryTypes, uint16(getTypeId(b)))
	}
	message := newMessage()
	message.setHeader(uint16(len(queryTypes)))
	message.setQuestion(domainName, parseQueryTypes)
	return message
}

func encodeDomain(domain string) []byte {
	splits := strings.Split(domain, ".")
	var encodedDomain []byte
	for _, spl := range splits {
		splLen := len(spl)
		encodedDomain = append(encodedDomain, byte(splLen))
		encodedDomain = append(encodedDomain, spl...)
	}

	return append(encodedDomain, '\x00')
}

func combineFlags(qr, opcode, aa, tc, rd, ra, z, rcode uint) uint16 {
	return uint16(qr<<15 | opcode<<11 | aa<<10 | tc<<9 | rd<<8 | ra<<7 | z<<4 | rcode)
}

func generateId() uint16 {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	num := uint16(r.Intn(1 << 16)) // 1 << 16 is 65536
	return num
}
