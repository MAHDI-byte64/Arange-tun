package client

import (
	"context"
	"time"
)

func (c *Client) ticker(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			// for _, tc := range c.iter.Items {
			// 	tc.sendTCPF(tc.conn)
			// }
			// timer.Reset(8 * time.Second)
		case <-ctx.Done():
			return
		}
	}
}
