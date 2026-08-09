package hash

import (
	"hash/maphash"
	"sync"
)

var seed = maphash.MakeSeed()
var hasherPool = sync.Pool{
	New: func() any {
		h := new(maphash.Hash)
		h.SetSeed(seed)
		return h
	},
}

func AddrPair(localAddr, targetAddr string) uint64 {
	h := hasherPool.Get().(*maphash.Hash)
	defer hasherPool.Put(h)

	h.Reset()
	h.WriteString(localAddr)
	h.WriteByte(0)
	h.WriteString(targetAddr)
	return h.Sum64()
}
