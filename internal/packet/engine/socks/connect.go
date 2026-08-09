package socks

import (
	"context"
	"net"

	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/flog"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/pkg/buffer"
)

func (s *Server) handleConnect(ctx context.Context, conn net.Conn, req *request) {
	strm, err := s.client.TCP(ctx, req.address())
	if err != nil {
		flog.Errorf("SOCKS5 failed to establish TCP stream for %s -> %s: %v", conn.RemoteAddr(), req.address(), err)
		s.write(conn, repFailure)
		return
	}
	defer strm.Close()
	flog.Infof("SOCKS5 accepted TCP connection %s -> %s", conn.RemoteAddr(), req.address())

	lAddr := conn.LocalAddr().(*net.TCPAddr)
	if _, err := conn.Write(append([]byte{ver, repSuccess, 0x00}, putAddr(nil, lAddr.IP, lAddr.Port)...)); err != nil {
		return
	}

	errCh := make(chan error, 2)
	go func() { errCh <- buffer.CopyT(conn, strm) }()
	go func() { errCh <- buffer.CopyT(strm, conn) }()

	select {
	case err := <-errCh:
		if err != nil {
			flog.Errorf("SOCKS5 TCP stream %d failed for %s -> %s: %v", strm.SID(), conn.RemoteAddr(), req.address(), err)
		}
	case <-ctx.Done():
	}

	flog.Debugf("SOCKS5 connection %s -> %s closed", conn.RemoteAddr(), req.address())
}
