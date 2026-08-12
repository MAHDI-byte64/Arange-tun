package webui

import (
	"fmt"
	"testing"
	"time"
)

func newTestLimiter() *loginLimiter {
	return &loginLimiter{fails: map[string]failCount{}, until: map[string]time.Time{}}
}

// Five failures lock the address out; a success wipes the slate.
func TestLoginLimiter(t *testing.T) {
	l := newTestLimiter()
	ip := "203.0.113.9"

	for i := 0; i < loginMaxFails-1; i++ {
		l.fail(ip)
		if b, _ := l.blocked(ip); b {
			t.Fatalf("blocked after %d failures", i+1)
		}
	}
	l.fail(ip)
	if b, _ := l.blocked(ip); !b {
		t.Fatal("not blocked after reaching the limit")
	}

	l.reset(ip)
	if b, _ := l.blocked(ip); b {
		t.Fatal("still blocked after reset")
	}
}

// The panel answers on a public port, so it is scanned: addresses that fail
// once and never come back are the common case, not the exception. Their tallies
// have to age out, or the two maps grow for as long as the panel runs.
func TestLoginLimiterForgetsStaleAddresses(t *testing.T) {
	l := newTestLimiter()

	// A thousand addresses, each one failure, all already past their window.
	for i := 0; i < 1000; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i)
		l.fail(ip)
		l.mu.Lock()
		f := l.fails[ip]
		f.exp = time.Now().Add(-time.Minute)
		l.fails[ip] = f
		l.mu.Unlock()
	}

	// The next failure from anywhere sweeps them.
	l.fail("203.0.113.1")

	l.mu.Lock()
	n := len(l.fails)
	l.mu.Unlock()
	if n != 1 {
		t.Fatalf("stale addresses kept: %d entries remain, want 1", n)
	}
}

// A failure that has aged out must not count towards the lockout, or the
// threshold quietly becomes "five failures ever" rather than five in a window.
func TestLoginLimiterCountsOnlyWithinTheWindow(t *testing.T) {
	l := newTestLimiter()
	ip := "203.0.113.7"

	for i := 0; i < loginMaxFails-1; i++ {
		l.fail(ip)
	}
	// Age the tally out, as a quiet hour would.
	l.mu.Lock()
	f := l.fails[ip]
	f.exp = time.Now().Add(-time.Minute)
	l.fails[ip] = f
	l.mu.Unlock()

	l.fail(ip)
	if b, _ := l.blocked(ip); b {
		t.Fatal("a lapsed tally still counted towards the lockout")
	}
}

// A code works exactly once; three wrong tries kill the pending login.
func TestTwoFAStore(t *testing.T) {
	st := &twoFAStore{pending: map[string]*pendingLogin{}}

	tok, code := st.start()
	if ok, _ := st.verify(tok, code); !ok {
		t.Fatal("correct code rejected")
	}
	if ok, dead := st.verify(tok, code); ok || !dead {
		t.Fatal("a code must not work twice")
	}

	tok, _ = st.start()
	for i := 0; i < twoFAMaxAttempts-1; i++ {
		if _, dead := st.verify(tok, "000000"); dead {
			t.Fatalf("killed after %d attempts", i+1)
		}
	}
	if _, dead := st.verify(tok, "000000"); !dead {
		t.Fatal("pending login should die after max attempts")
	}
}
