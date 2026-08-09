package server

import (
	"context"
	"fmt"

	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/conf"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/flog"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/tnet"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/tnet/kcp"
)

type Server struct {
	cfg      *conf.Conf
	listener tnet.Listener
}

func New(cfg *conf.Conf) (*Server, error) {
	s := &Server{cfg: cfg}
	return s, nil
}

func (s *Server) Start(ctx context.Context) error {
	listener, err := kcp.Listen(s.cfg.Transport.KCP, s.cfg.Network)
	if err != nil {
		return fmt.Errorf("could not start KCP listener: %w", err)
	}
	s.listener = listener
	flog.Infof("Server started - listening for packets on :%d", s.cfg.Listen.Addr.Port)

	go s.listen(ctx, listener)
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	return nil
}

func (s *Server) listen(ctx context.Context, listener tnet.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		flog.Infof("accepted new connection from %s (local: %s)", conn.RemoteAddr(), conn.LocalAddr())

		go func() {
			defer conn.Close()
			defer s.listener.DeleteClientTCPF(conn.RemoteAddr())
			s.handleConn(ctx, conn)
		}()
	}
}
