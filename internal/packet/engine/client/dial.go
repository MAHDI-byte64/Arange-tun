package client

import (
	"context"
	"errors"
	"time"

	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/flog"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/tnet"
)

// errNilConn marks a pool slot whose connection is absent (a keepalive re-dial
// failed), so newConn recreates it instead of dereferencing nil.
var errNilConn = errors.New("connection not established")

func (c *Client) newConn() (tnet.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	autoExpire := 300
	tc := c.iter.Next()
	// The TCP-flags profile (PTCPF) is a per-connection handshake that
	// createConn() already sends once when it dials. Re-sending it on every
	// newConn — as a fire-and-forget goroutine, on a connection about to be
	// health-checked and possibly closed — is redundant: it opens a throwaway
	// stream each time (every reused stream and every liveness poll) and leaks a
	// goroutine per call, which on an idle tunnel piled up unboundedly over
	// hours. So it is only sent where it belongs, inside createConn below.
	// tc.conn is nil when a background keepalive re-dial has failed and left the
	// slot empty; treat that the same as a failed liveness probe. Guarding here
	// also stops a nil dereference on that path.
	var err error
	if tc.conn == nil {
		err = errNilConn
	} else {
		err = tc.conn.Ping(false)
	}
	if err != nil {
		flog.Infof("connection lost, retrying....")
		if tc.conn != nil {
			tc.conn.Close()
		}
		conn, err := tc.createConn()
		if err != nil {
			return nil, err
		}
		tc.conn = conn
		tc.expire = time.Now().Add(time.Duration(autoExpire) * time.Second)
	}
	return tc.conn, nil
}

// retryBackoff is how long newStrm waits after a failed attempt.
//
// It retried with no pause at all, which is fine while the server is answering
// — the loop runs once — and pathological when it is not: a dial that fails
// immediately (no route, port unreachable) span this loop as fast as the CPU
// allowed, spawning a sendTCPF goroutine per turn, for as long as the caller
// waited. A short sleep costs nothing on the working path and turns the broken
// one from a busy-wait into a poll.
const retryBackoff = 250 * time.Millisecond

func (c *Client) newStrm(ctx context.Context) (tnet.Strm, error) {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if attempt > 0 {
			// Interruptible: a caller that gave up should not wait out the sleep.
			select {
			case <-time.After(retryBackoff):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		conn, err := c.newConn()
		if err != nil {
			flog.Debugf("failed to open conn, retrying: %v", err)
			continue
		}
		strm, err := conn.OpenStrm()
		if err != nil {
			flog.Debugf("failed to open stream, retrying: %v", err)
			continue
		}
		return strm, nil
	}
}
