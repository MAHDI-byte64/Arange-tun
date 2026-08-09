package client

import (
	"context"
	"time"

	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/flog"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/tnet"
)

func (c *Client) newConn() (tnet.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	autoExpire := 300
	tc := c.iter.Next()
	go tc.sendTCPF(tc.conn)
	err := tc.conn.Ping(false)
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

func (c *Client) newStrm(ctx context.Context) (tnet.Strm, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
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
