package server

import (
	"context"
	"fmt"
	"sync"

	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/conf"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/flog"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/tnet"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/tnet/kcp"
)

type Server struct {
	cfg      *conf.Conf
	listener tnet.Listener

	// Live client connections, by remote address. The raw session has no socket
	// in the kernel's tables — that is the whole point of this transport — so
	// nothing outside this process can tell whether a client is actually
	// connected. Accept and close are the only two moments that know, so they
	// are recorded here and published through Peers(). Counted rather than
	// stored as a set because one client opens several connections (one per
	// conf.Transport.Conn) and the peer is only gone when the last one is.
	mu    sync.Mutex
	peers map[string]int
}

func New(cfg *conf.Conf) (*Server, error) {
	s := &Server{cfg: cfg, peers: make(map[string]int)}
	return s, nil
}

// Peers returns the addresses of the clients currently connected. The slice is
// a copy, safe to hold and to sort.
func (s *Server) Peers() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.peers))
	for addr := range s.peers {
		out = append(out, addr)
	}
	return out
}

func (s *Server) addPeer(addr string) {
	s.mu.Lock()
	s.peers[addr]++
	s.mu.Unlock()
}

func (s *Server) removePeer(addr string) {
	s.mu.Lock()
	if n := s.peers[addr] - 1; n > 0 {
		s.peers[addr] = n
	} else {
		delete(s.peers, addr)
	}
	s.mu.Unlock()
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

		remote := conn.RemoteAddr()
		s.addPeer(remote.String())
		go func() {
			defer conn.Close()
			defer s.removePeer(remote.String())
			defer s.listener.DeleteClientTCPF(remote)
			s.handleConn(ctx, conn)
		}()
	}
}
