package pool

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// fakeConn is a no-op net.Conn for exercising monitoredStream in isolation.
type fakeConn struct{}

func (fakeConn) Read([]byte) (int, error)         { return 0, nil }
func (fakeConn) Write(b []byte) (int, error)      { return len(b), nil }
func (fakeConn) Close() error                     { return nil }
func (fakeConn) LocalAddr() net.Addr              { return nil }
func (fakeConn) RemoteAddr() net.Addr             { return nil }
func (fakeConn) SetDeadline(time.Time) error      { return nil }
func (fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeConn) SetWriteDeadline(time.Time) error { return nil }

// TestMonitoredStreamCloseUnblocksRateLimit verifies that closing a stream
// cancels its context so a goroutine parked in the token-bucket WaitN returns
// promptly instead of waiting out the full delay (no goroutine leak on a dead
// connection).
func TestMonitoredStreamCloseUnblocksRateLimit(t *testing.T) {
	// 1 byte/sec with a 4-byte burst; drain the burst so any further wait is slow.
	ys := &YamuxSession{limiter: rate.NewLimiter(1, 4)}
	ys.limiter.AllowN(time.Now(), 4)

	ctx, cancel := context.WithCancel(context.Background())
	ms := &monitoredStream{Conn: fakeConn{}, parent: ys, ctx: ctx, cancel: cancel}

	start := time.Now()
	if err := ms.Close(); err != nil { // cancels ctx
		t.Fatalf("close: %v", err)
	}
	if _, err := ms.Write([]byte("payload-larger-than-burst")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Write blocked %v despite a canceled context", elapsed)
	}

	select {
	case <-ms.ctx.Done():
	default:
		t.Fatal("Close did not cancel the stream context")
	}
}

// TestChaosLimitBounds verifies the fluctuating DPI-evasion cap: with no jitter it
// equals the base, with jitter it stays within [base-jitter, base+jitter], and it
// never falls below 1 Mbps even when jitter exceeds the base.
func TestChaosLimitBounds(t *testing.T) {
	// No jitter -> exact base.
	s := &YamuxSession{baseLimitMbps: 20, jitterMbps: 0}
	s.UpdateChaosLimit()
	if got := s.CurrentCap(); got != 20 {
		t.Fatalf("no-jitter cap = %d, want 20", got)
	}

	// With jitter -> always within band, over many draws.
	s = &YamuxSession{baseLimitMbps: 40, jitterMbps: 15}
	for i := 0; i < 500; i++ {
		s.UpdateChaosLimit()
		c := s.CurrentCap()
		if c < 40-15 || c > 40+15 {
			t.Fatalf("cap %d out of [25,55]", c)
		}
	}

	// Jitter larger than base must still floor at 1 (never 0/negative).
	s = &YamuxSession{baseLimitMbps: 3, jitterMbps: 10}
	for i := 0; i < 500; i++ {
		s.UpdateChaosLimit()
		if c := s.CurrentCap(); c < 1 {
			t.Fatalf("cap %d below floor of 1", c)
		}
	}
}

// TestGetAndResetBytes verifies the atomic byte counter fetch-and-reset.
func TestGetAndResetBytes(t *testing.T) {
	s := &YamuxSession{}
	s.bytesTransferred = 4096
	if got := s.GetAndResetBytes(); got != 4096 {
		t.Fatalf("GetAndResetBytes = %d, want 4096", got)
	}
	if got := s.GetAndResetBytes(); got != 0 {
		t.Fatalf("counter not reset: %d", got)
	}
}

// TestDrainingState verifies the Active/Draining lifecycle transitions.
func TestDrainingState(t *testing.T) {
	s := &YamuxSession{state: StateActive}
	if !s.IsActive() || s.IsDraining() {
		t.Fatal("initial state should be Active")
	}
	s.SetDraining()
	if s.IsActive() || !s.IsDraining() {
		t.Fatal("after SetDraining should be Draining")
	}
	s.Revive()
	if !s.IsActive() || s.IsDraining() {
		t.Fatal("after Revive should be Active")
	}
}
