package server

import (
	"context"
	"net"
	"time"

	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/flog"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/pkg/buffer"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/protocol"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/tnet"
)

func (s *Server) handleUDPProtocol(ctx context.Context, strm tnet.Strm, p *protocol.Proto) {
	flog.Infof("accepted UDP stream %d: %s -> %s", strm.SID(), strm.RemoteAddr(), p.Addr.String())
	s.handleUDP(ctx, strm, p.Addr.String())
}

func (s *Server) handleUDP(ctx context.Context, strm tnet.Strm, addr string) {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		flog.Errorf("failed to establish UDP connection to %s for stream %d: %v", addr, strm.SID(), err)
		return
	}
	defer func() {
		conn.Close()
		flog.Debugf("closed UDP connection %s for stream %d", addr, strm.SID())
	}()

	errChan := make(chan error, 2)
	go func() { errChan <- buffer.CopyU(conn, strm) }()
	go func() { errChan <- buffer.CopyU(strm, conn) }()

	select {
	case err := <-errChan:
		if err != nil {
			flog.Errorf("UDP stream %d failed for %s -> %s: %v", strm.SID(), conn.RemoteAddr(), addr, err)
		}
	case <-ctx.Done():
	}
}
