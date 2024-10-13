package dns

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
