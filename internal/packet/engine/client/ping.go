package client

import (
	"context"
	"fmt"

	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/protocol"
)

// Ping asks the server to answer, and returns nil only when it does.
//
// It is the client's one honest liveness signal. The raw session carries no
// socket the kernel can be asked about, and the connections are created once at
// startup and re-dialed lazily, so "the process is running" says nothing about
// whether the far end is still there. A PPING that comes back as a PPONG says
// the whole path works: packets are injected, captured, the KCP session is
// live, and something on the other side is still answering.
//
// ctx bounds the whole exchange. newStrm retries until it succeeds, so without
// a deadline this would block for as long as the server stayed unreachable —
// pass a context with a timeout.
func (c *Client) Ping(ctx context.Context) error {
	strm, err := c.newStrm(ctx)
	if err != nil {
		return err
	}
	defer strm.Close()

	// The stream blocks in Read below, which no context can interrupt on its
	// own; closing it from here is what unblocks that read when ctx ends.
	stop := context.AfterFunc(ctx, func() { strm.Close() })
	defer stop()

	p := protocol.Proto{Type: protocol.PPING}
	if err := p.Write(strm); err != nil {
		return err
	}
	var reply protocol.Proto
	if err := reply.Read(strm); err != nil {
		return err
	}
	if reply.Type != protocol.PPONG {
		return fmt.Errorf("unexpected reply type %d", reply.Type)
	}
	return nil
}
