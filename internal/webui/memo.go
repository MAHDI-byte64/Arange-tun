package webui

import (
	"sync"
	"time"
)

// memo caches an expensive lookup under a string key for a while.
//
// It exists because the panel refreshes its tunnel list every six seconds and
// re-measured everything from scratch each time: a ping subprocess per tunnel
// and, for any tunnel addressed by name, a DNS lookup per tunnel. Neither
// answer changes on that timescale, so almost all of that work was spent
// producing a number the page already had. A short time-to-live keeps the
// display live while collapsing the repeats.
type memo[T any] struct {
	mu  sync.Mutex
	ttl time.Duration
	// ttlFor, when set, chooses the lifetime from the value itself, so a
	// result worth rechecking sooner can say so. See pingMemo.
	ttlFor  func(T) time.Duration
	entries map[string]memoEntry[T]
}

type memoEntry[T any] struct {
	val T
	exp time.Time
}

func newMemo[T any](ttl time.Duration) *memo[T] {
	return &memo[T]{ttl: ttl, entries: make(map[string]memoEntry[T])}
}

// get returns the cached value for key, computing it when there is none or the
// one there has expired.
//
// compute runs without the lock held: the calls this caches take up to a second
// each and are made from one goroutine per tunnel, so holding the lock across
// them would turn a parallel refresh into a serial one — the opposite of the
// point. Two goroutines racing on a cold key may both compute, which costs one
// extra probe and settles immediately.
func (m *memo[T]) get(key string, compute func() T) T {
	m.mu.Lock()
	e, ok := m.entries[key]
	m.mu.Unlock()
	if ok && time.Now().Before(e.exp) {
		return e.val
	}

	v := compute()
	ttl := m.ttl
	if m.ttlFor != nil {
		ttl = m.ttlFor(v)
	}

	m.mu.Lock()
	m.entries[key] = memoEntry[T]{val: v, exp: time.Now().Add(ttl)}
	// The key space is bounded by the number of tunnels and their peers, so
	// this cannot grow without limit in normal use. Expired entries are still
	// dropped here so a machine whose tunnels are edited often does not
	// accumulate addresses it will never look at again.
	if len(m.entries) > memoMaxEntries {
		now := time.Now()
		for k, old := range m.entries {
			if now.After(old.exp) {
				delete(m.entries, k)
			}
		}
	}
	m.mu.Unlock()
	return v
}

// memoMaxEntries is when a sweep for expired entries becomes worth doing. Well
// above any real tunnel count, so the sweep never runs on a normal machine.
const memoMaxEntries = 256

// How long each measurement stands in for the next one.
//
// A latency that came back is a stable fact and does not need re-measuring
// every six seconds. A probe that failed is not: it is the reading that turns a
// card red, and the one most likely to change next, so it is rechecked sooner —
// which is what keeps a tunnel from looking dead long after it recovered.
// A name's address changes far more rarely than either.
const (
	pingTTL       = 30 * time.Second
	pingFailedTTL = 8 * time.Second
	dnsTTL        = 5 * time.Minute
)

var (
	pingMemo = newPingMemo()
	dnsMemo  = newMemo[string](dnsTTL)
)

func newPingMemo() *memo[int] {
	m := newMemo[int](pingTTL)
	m.ttlFor = func(rtt int) time.Duration {
		if rtt < 0 { // unreachable, blocked, or timed out
			return pingFailedTTL
		}
		return pingTTL
	}
	return m
}
