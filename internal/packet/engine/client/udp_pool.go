package client

import (
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/flog"
	"github.com/mahdi-byte64/arange-tun/internal/packet/engine/tnet"
	"sync"
)

type udpPool struct {
	strms map[uint64]tnet.Strm
	mu    sync.RWMutex
}

func (p *udpPool) delete(key uint64) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if strm, exists := p.strms[key]; exists {
		flog.Debugf("closing UDP session stream %d", strm.SID())
		strm.Close()
	} else {
		flog.Debugf("UDP session key %d not found for close", key)
	}
	delete(p.strms, key)

	return nil
}
