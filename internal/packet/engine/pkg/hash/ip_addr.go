package hash

import (
	"encoding/binary"
	"net"
)

func IPAddr(ip net.IP, port uint16) uint64 {
	if len(ip) == 4 {
		hash := uint64(binary.BigEndian.Uint32(ip))<<16 | uint64(port)
		return hash
	}
	ip16 := ip.To16()
	hash := binary.BigEndian.Uint64(ip16[0:8]) ^ binary.BigEndian.Uint64(ip16[8:16])
	hash = hash ^ (uint64(port) << 48)
	return hash
}
