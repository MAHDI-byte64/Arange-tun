package kcp

import (
	"fmt"
	"net"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"

	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/conf"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/socket"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/tnet"
)

func Dial(addr *net.UDPAddr, cfg *conf.KCP, netCfg conf.Network) (tnet.Conn, error) {
	nCfg := netCfg
	packetConn, err := socket.New(&nCfg)
	if err != nil {
		return nil, fmt.Errorf("kcp: failed to create packetconn: %w", err)
	}

	conn, err := kcp.NewConn(addr.String(), cfg.Block, cfg.Dshard, cfg.Pshard, packetConn)
	if err != nil {
		packetConn.Close()
		return nil, fmt.Errorf("kcp: failed to dial connection: %w", err)
	}
	aplConf(conn, cfg)

	sess, err := smux.Client(conn, smuxConf(cfg))
	if err != nil {
		conn.Close()
		packetConn.Close()
		return nil, fmt.Errorf("kcp: failed to create smux session: %w", err)
	}

	return &Conn{packetConn, conn, sess}, nil
}
