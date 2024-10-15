package dns

type DNSMesage struct {
	Header        DNSHeader
	Question      []DNSQuestion
	Answer        []DNSRR
	Authoritative []DNSRR
	Additional    []DNSRR
}

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

// DNS record types
const (
	TypeA     = 1  // A record
	TypeNS    = 2  // NS record
	TypeCNAME = 5  // CNAME record
	TypeSOA   = 6  // SOA record
	TypePTR   = 12 // PTR record
	TypeMX    = 15 // MX record
	TypeTXT   = 16 // TXT record
	TypeAAAA  = 28 // AAAA record
	TypeSRV   = 33 // SRV record
	TypeOPT   = 41 // OPT record
)

// DNS classes
const (
	ClassIN = 1 // Internet (IN)
	ClassCS = 2 // CSNET (CS)
	ClassCH = 3 // CHAOS (CH)
	ClassHS = 4 // Hesiod (HS)
)

// Mapping for record types
var typeToString = map[uint16]string{
	TypeA:     "A",
	TypeNS:    "NS",
	TypeCNAME: "CNAME",
	TypeSOA:   "SOA",
	TypePTR:   "PTR",
	TypeMX:    "MX",
	TypeTXT:   "TXT",
	TypeAAAA:  "AAAA",
	TypeSRV:   "SRV",
	TypeOPT:   "OPT",
}

// Mapping for classes
var classToString = map[uint16]string{
	ClassIN: "IN",
	ClassCS: "CS",
	ClassCH: "CH",
	ClassHS: "HS",
}

// Reverse maps for looking up ID by name
var (
	stringToType  = make(map[string]uint16)
	stringToClass = make(map[string]uint16)
)

// Initialize reverse maps
func init() {
	for k, v := range typeToString {
		stringToType[v] = k
	}
	for k, v := range classToString {
		stringToClass[v] = k
	}
}

// Function to get the string representation of a DNS type
func getTypeString(recordType uint16) string {
	if str, exists := typeToString[recordType]; exists {
		return str
	}
	return "UNKNOWN"
}

// Function to get the id representation of a DNS type from string
func getTypeId(record string) uint16 {
	if id, exits := stringToType[record]; exits {
		return id
	}
	return 0
}

// Function to get the string representation of a DNS class
func getClassString(class uint16) string {
	if str, exists := classToString[class]; exists {
		return str
	}
	return "UNKNOWN"
}

// Function to get the class uint16 for the string representation
func getClassId(class string) uint16 {
	if id, exists := stringToClass[class]; exists {
		return id
	}
	return 0
}
