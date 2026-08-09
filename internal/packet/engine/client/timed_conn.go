package client

import (
	"time"

	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/conf"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/protocol"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/tnet"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/tnet/kcp"
)

type timedConn struct {
	cfg    *conf.Conf
	conn   tnet.Conn
	expire time.Time
}

func newTimedConn(cfg *conf.Conf) (*timedConn, error) {
	var err error
	tc := timedConn{cfg: cfg}
	tc.conn, err = tc.createConn()
	if err != nil {
		return nil, err
	}

	return &tc, nil
}

func (tc *timedConn) createConn() (tnet.Conn, error) {
	conn, err := kcp.Dial(tc.cfg.Server.Addr, tc.cfg.Transport.KCP, tc.cfg.Network)
	if err != nil {
		return nil, err
	}
	err = tc.sendTCPF(conn)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (tc *timedConn) sendTCPF(conn tnet.Conn) error {
	strm, err := conn.OpenStrm()
	if err != nil {
		return err
	}
	defer strm.Close()

	p := protocol.Proto{Type: protocol.PTCPF, TCPF: tc.cfg.Network.TCP.RF}
	err = p.Write(strm)
	if err != nil {
		return err
	}
	return nil
}

func (tc *timedConn) close() {
	if tc.conn != nil {
		tc.conn.Close()
	}
}
