package tnet

import (
	"net"
	"time"
)

type Conn interface {
	OpenStrm() (Strm, error)
	AcceptStrm() (Strm, error)
	Ping(wait bool) error
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}
