package tnet

import (
	"net"
)

type Strm interface {
	net.Conn
	SID() int
}
