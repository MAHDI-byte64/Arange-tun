package client

import (
	"context"

	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/flog"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/protocol"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/tnet"
)

func (c *Client) TCP(ctx context.Context, addr string) (tnet.Strm, error) {
	strm, err := c.newStrm(ctx)
	if err != nil {
		flog.Debugf("failed to create stream for TCP %s: %v", addr, err)
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { strm.Close() })
	defer stop()

	tAddr, err := tnet.NewAddr(addr)
	if err != nil {
		flog.Debugf("invalid TCP address %s: %v", addr, err)
		strm.Close()
		return nil, err
	}

	p := protocol.Proto{Type: protocol.PTCP, Addr: tAddr}
	err = p.Write(strm)
	if err != nil {
		flog.Debugf("failed to write TCP protocol for %s on stream %d: %v", addr, strm.SID(), err)
		strm.Close()
		return nil, err
	}

	flog.Debugf("TCP stream %d created for %s", strm.SID(), addr)
	return strm, nil
}
