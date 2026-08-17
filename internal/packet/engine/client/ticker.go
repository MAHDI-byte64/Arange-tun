package client

import (
	"context"
	"time"

	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/flog"
)

// keepAliveInterval is how often the client checks its connections. It is well
// under the smux keepalive timeout (8s) so a connection that has gone quiet is
// re-dialed before an incoming stream would ever land on a dead one — the entry
// node then always has a warm connection ready, instead of the first byte of
// user traffic paying for a reconnect.
const keepAliveInterval = 4 * time.Second

// ticker keeps the pooled connections alive and healthy.
//
// The raw crafted-packet path this tunnel rides on is frequently lossy or thinned
// out by a DPI box, so an idle connection's smux/KCP session can die between uses.
// This loop proactively probes each connection and re-dials the dead ones, which
// does two things on a marginal route: it keeps at least some connections warm at
// all times, and a re-dial moves that connection to a fresh source port — which
// slips past a stateful middlebox that had started dropping the old flow.
func (c *Client) ticker(ctx context.Context) {
	t := time.NewTicker(keepAliveInterval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.keepAlive()
		}
	}
}

// keepAlive probes every pooled connection and re-dials the ones that have died.
// It takes the same lock newConn does, so it never races a stream open or another
// heal; connection creation is serialized across the client either way.
func (c *Client) keepAlive() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, tc := range c.iter.Items {
		if tc.conn != nil && tc.conn.Ping(false) == nil {
			continue // still healthy — leave it be
		}
		if tc.conn != nil {
			tc.conn.Close()
		}
		conn, err := tc.createConn()
		if err != nil {
			// Leave it nil; the next tick (or an on-demand newConn) retries. Do
			// not spin here — the interval is the backoff.
			tc.conn = nil
			flog.Debugf("keepalive: reconnect failed, will retry: %v", err)
			continue
		}
		tc.conn = conn
		tc.expire = time.Now().Add(300 * time.Second)
	}
}
