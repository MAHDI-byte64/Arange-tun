package tlscert

import (
	"crypto/tls"
	"testing"

	"golang.org/x/crypto/acme"
)

// TestCertManagerSelfSignedFallback: with no domain, GetCertificate always returns
// the self-signed cert and ACME is not configured.
func TestCertManagerSelfSignedFallback(t *testing.T) {
	cm, err := NewCertManager(t.TempDir(), "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if cm.ACMEConfigured() {
		t.Fatal("no domain must mean ACME is not configured")
	}
	c, err := cm.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || c == nil || len(c.Certificate) == 0 {
		t.Fatalf("expected the self-signed cert, got %v (err %v)", c, err)
	}
	// SelfSignedCertificate returns the same fallback regardless of hello.
	if c2, _ := cm.SelfSignedCertificate(&tls.ClientHelloInfo{ServerName: "anything"}); c2 == nil || len(c2.Certificate) == 0 {
		t.Fatal("SelfSignedCertificate must always serve the self-signed cert")
	}
	// HTTP/1.1 only (never h2 — the decoys speak HTTP/1.1; h2 would break a browser
	// hitting the decoy).
	if got := cm.NextProtos(); len(got) != 1 || got[0] != "http/1.1" {
		t.Fatalf("NextProtos without ACME = %v, want [http/1.1]", got)
	}
}

// TestCertManagerACMEConfigured: with a domain, the ACME manager exists and the
// ALPN proto is advertised — but until DNS is confirmed, normal handshakes still
// fall back to self-signed (never break).
func TestCertManagerACMEConfigured(t *testing.T) {
	cm, err := NewCertManager(t.TempDir(), "example.com", "ops@example.com", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !cm.ACMEConfigured() {
		t.Fatal("a domain must configure ACME")
	}
	got := cm.NextProtos()
	if len(got) != 2 || got[0] != "http/1.1" || got[1] != acme.ALPNProto {
		t.Fatalf("NextProtos with ACME must be [http/1.1, %q], got %v", acme.ALPNProto, got)
	}
	// active is false at construction (DNS not yet confirmed) -> self-signed served.
	c, err := cm.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil || c == nil || len(c.Certificate) == 0 {
		t.Fatalf("pre-activation handshake must fall back to self-signed, got %v (err %v)", c, err)
	}
}

// TestDNSPointsHereUnresolvable: a domain that cannot resolve returns false with an
// explanatory detail (so ACME is not attempted against a dead name).
func TestDNSPointsHereUnresolvable(t *testing.T) {
	ok, detail := dnsPointsHere("nonexistent-host.invalid")
	if ok {
		t.Fatalf("an unresolvable domain must not be treated as pointing here (detail: %s)", detail)
	}
}

// TestLocalPublicIPsExcludesLoopback: the helper must never return loopback or
// private addresses (they would make the DNS check meaningless).
func TestLocalPublicIPsExcludesLoopback(t *testing.T) {
	for _, ip := range localPublicIPs() {
		if ip.IsLoopback() || ip.IsPrivate() || !ip.IsGlobalUnicast() {
			t.Fatalf("localPublicIPs returned a non-public address: %s", ip)
		}
	}
}
