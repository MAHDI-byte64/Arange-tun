package kcp

import (
	"github.com/xtaci/smux"
)

type Strm struct {
	*smux.Stream
}

func (s *Strm) SID() int {
	return int(s.ID())
}
