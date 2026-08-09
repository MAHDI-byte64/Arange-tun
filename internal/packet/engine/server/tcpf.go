package server

import (
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/protocol"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/tnet"
)

func (s *Server) handleTCPF(strm tnet.Strm, p *protocol.Proto) {
	if len(p.TCPF) == 0 {
		s.listener.DeleteClientTCPF(strm.RemoteAddr())
		return
	}
	s.listener.SetClientTCPF(strm.RemoteAddr(), p.TCPF)
}
