package spoof

import (
	"net"
	"testing"
)

func TestAEADRoundTrip(t *testing.T) {
	a, err := newAEAD("secret")
	if err != nil {
		t.Fatalf("newAEAD: %v", err)
	}
	msg := []byte("wireguard handshake bytes")
	frame, err := a.seal(msg)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := a.open(frame)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("round-trip = %q, want %q", got, msg)
	}
	// Two seals of the same payload differ (random nonce).
	f2, _ := a.seal(msg)
	if string(frame) == string(f2) {
		t.Fatalf("two seals produced identical frames — nonce not random")
	}
}

func TestAEADWrongKeyRejected(t *testing.T) {
	a, _ := newAEAD("one")
	b, _ := newAEAD("two")
	frame, _ := a.seal([]byte("hi"))
	if _, err := b.open(frame); err == nil {
		t.Fatalf("a frame sealed with a different key was accepted")
	}
	if _, err := a.open([]byte("garbage")); err == nil {
		t.Fatalf("a too-short/garbage frame was accepted")
	}
}

func TestExpandIPs(t *testing.T) {
	// single
	got, err := ExpandIPs("1.2.3.4", 0)
	if err != nil || len(got) != 1 || got[0] != "1.2.3.4" {
		t.Fatalf("single = %v err=%v", got, err)
	}
	// full range
	got, _ = ExpandIPs("1.2.3.4-1.2.3.6", 0)
	if len(got) != 3 || got[0] != "1.2.3.4" || got[2] != "1.2.3.6" {
		t.Fatalf("range = %v", got)
	}
	// short range
	got, _ = ExpandIPs("10.0.0.1-3", 0)
	if len(got) != 3 || got[2] != "10.0.0.3" {
		t.Fatalf("short range = %v", got)
	}
	// CIDR /30 = 4 addresses
	got, _ = ExpandIPs("192.168.1.0/30", 0)
	if len(got) != 4 {
		t.Fatalf("cidr /30 = %v", got)
	}
	// mixed + dedup
	got, _ = ExpandIPs("1.1.1.1, 1.1.1.1, 2.2.2.0/31", 0)
	if len(got) != 3 {
		t.Fatalf("mixed dedup = %v", got)
	}
	// cap
	got, _ = ExpandIPs("10.0.0.0/16", 10)
	if len(got) != 10 {
		t.Fatalf("cap = %d, want 10", len(got))
	}
	// invalid
	if _, err := ExpandIPs("not-an-ip", 0); err == nil {
		t.Fatalf("expected error for invalid input")
	}
}

func TestProbeRoundTrip(t *testing.T) {
	src := net.ParseIP("9.8.7.6")
	frame := buildProbe(src)
	if ip := parseProbe(frame); ip != "9.8.7.6" {
		t.Fatalf("parseProbe = %q, want 9.8.7.6", ip)
	}
	if ip := parseProbe([]byte("nope")); ip != "" {
		t.Fatalf("parseProbe of junk = %q, want empty", ip)
	}
}
