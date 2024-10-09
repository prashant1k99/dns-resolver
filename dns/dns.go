package dns

import (
	"math/rand"
	"time"
)

func GenerateId() uint16 {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	num := uint16(r.Intn(1 << 16)) // 1 << 16 is 65536
	return num
}
