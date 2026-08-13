package tlscert

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// CertManager decides, per TLS handshake, which certificate the mimic presents:
//
//   - If a Domain is configured AND its A/AAAA records point at this server, a real
//     Let's Encrypt certificate is obtained and auto-renewed via ACME (the strongest
//     defence against passive certificate fingerprinting).
//   - Otherwise (no domain, DNS not yet pointing, or any ACME failure) it falls back
//     to the self-signed cert. The handshake is NEVER broken by an ACME problem.
//
// It self-heals: if the domain does not resolve to us at boot, a background loop
// keeps checking and activates ACME the moment DNS is corrected — no restart needed.
type CertManager struct {
	selfSigned tls.Certificate
	selfFP     [32]byte
	domain     string

	mu     sync.RWMutex
	mgr    *autocert.Manager // nil until a domain is configured
	active bool              // true once DNS is confirmed to point here
}

// NewCertManager always loads/creates the self-signed fallback. If domain != "" it
// prepares an ACME manager and starts the DNS-gated activation loop.
func NewCertManager(dir, domain, email, serverName string) (*CertManager, error) {
	self, err := LoadOrCreate(dir, serverName)
	if err != nil {
		return nil, err
	}
	fp, err := LeafFingerprint(&self)
	if err != nil {
		return nil, err
	}
	cm := &CertManager{selfSigned: self, selfFP: fp, domain: domain}

	if domain == "" {
		slog.Warn("TLS mimic using a self-signed certificate — set a domain for a real Let's Encrypt cert (much harder to fingerprint)")
		return cm, nil
	}

	cm.mgr = &autocert.Manager{
		Cache:      autocert.DirCache(filepath.Join(dir, "acme")),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Email:      email,
	}
	go cm.activateWhenDNSReady()
	return cm, nil
}

// GetCertificate is the tls.Config callback. ACME TLS-ALPN-01 challenges are always
// served (they must be, for issuance to work); real certs are served once DNS is
// confirmed; everything else falls back to self-signed.
func (cm *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cm.mu.RLock()
	mgr, active := cm.mgr, cm.active
	cm.mu.RUnlock()

	if mgr != nil {
		// A TLS-ALPN-01 validation handshake — must be answered by autocert.
		for _, p := range hello.SupportedProtos {
			if p == acme.ALPNProto {
				if c, err := mgr.GetCertificate(hello); err == nil {
					return c, nil
				}
				return &cm.selfSigned, nil
			}
		}
		if active {
			h := hello
			if hello.ServerName == "" { // serve the real cert even to no-SNI probes
				hc := *hello
				hc.ServerName = cm.domain
				h = &hc
			}
			if c, err := mgr.GetCertificate(h); err == nil && c != nil {
				return c, nil
			}
			// Any ACME error: fall through to self-signed, never break the handshake.
		}
	}
	return &cm.selfSigned, nil
}

// SelfSignedFingerprint returns the fallback cert's leaf fingerprint.
func (cm *CertManager) SelfSignedFingerprint() [32]byte { return cm.selfFP }

// SelfSignedCertificate is a GetCertificate callback that always serves the
// self-signed cert, regardless of domain/ACME. Used by the DirectAdmin (:2222)
// mimic, where a self-signed certificate is authentic (real panels use one) and a
// real CA cert would be out of place.
func (cm *CertManager) SelfSignedCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return &cm.selfSigned, nil
}

// ACMEConfigured reports whether a domain-backed ACME manager exists (regardless of
// current activation), so callers can wire the HTTP-01 handler / ALPN proto.
func (cm *CertManager) ACMEConfigured() bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.mgr != nil
}

// NextProtos returns the ALPN protocols the mimic's tls.Config should advertise.
// HTTP/1.1 only (the decoys speak HTTP/1.1; advertising h2 would break a real
// browser hitting the decoy), plus the ACME proto so TLS-ALPN-01 works on :443.
func (cm *CertManager) NextProtos() []string {
	if cm.ACMEConfigured() {
		return []string{"http/1.1", acme.ALPNProto}
	}
	return []string{"http/1.1"}
}

// HTTPChallengeHandler wraps the given fallback with autocert's HTTP-01 handler
// (serving /.well-known/acme-challenge/...). Returns fallback unchanged if no ACME.
func (cm *CertManager) HTTPChallengeHandler(fallback http.Handler) http.Handler {
	cm.mu.RLock()
	mgr := cm.mgr
	cm.mu.RUnlock()
	if mgr == nil {
		return fallback
	}
	return mgr.HTTPHandler(fallback)
}

// activateWhenDNSReady blocks ACME until the domain actually resolves to this
// server, then warms the certificate and keeps it renewed. This avoids hammering
// Let's Encrypt's rate limits with challenges that cannot possibly pass.
func (cm *CertManager) activateWhenDNSReady() {
	backoff := 15 * time.Second
	for {
		if ok, detail := dnsPointsHere(cm.domain); ok {
			slog.Info("domain resolves to this server; enabling ACME", "domain", cm.domain, "detail", detail)
			cm.mu.Lock()
			cm.active = true
			cm.mu.Unlock()
			cm.warmAndRenew()
			return
		} else {
			slog.Warn("domain does not point here yet; serving self-signed and re-checking (no ACME attempt)", "domain", cm.domain, "detail", detail, "retry_in", backoff.String())
		}
		time.Sleep(backoff)
		if backoff < 10*time.Minute {
			backoff *= 2
		}
	}
}

// warmAndRenew obtains the certificate up front (with backoff on failure) and then
// re-checks periodically so renewal happens well before expiry. autocert renews
// lazily; this forces the check and logs failures without ever breaking traffic.
func (cm *CertManager) warmAndRenew() {
	backoff := 30 * time.Second
	for {
		if err := cm.obtain(); err == nil {
			slog.Info("ACME certificate ready", "domain", cm.domain)
			break
		} else {
			slog.Warn("ACME issuance failed; retrying (self-signed served meanwhile)", "domain", cm.domain, "err", err, "retry_in", backoff.String())
			time.Sleep(backoff)
			if backoff < 30*time.Minute {
				backoff *= 2
			}
		}
	}
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		if err := cm.obtain(); err != nil {
			slog.Warn("ACME renew check failed; cached cert still served until it nears expiry", "domain", cm.domain, "err", err)
		}
	}
}

// obtain forces autocert to fetch-or-renew the domain cert.
func (cm *CertManager) obtain() error {
	cm.mu.RLock()
	mgr := cm.mgr
	cm.mu.RUnlock()
	if mgr == nil {
		return fmt.Errorf("acme manager not configured")
	}
	_, err := mgr.GetCertificate(&tls.ClientHelloInfo{
		ServerName:      cm.domain,
		SupportedProtos: []string{"http/1.1"},
	})
	return err
}

// dnsPointsHere reports whether the domain's A/AAAA records include one of this
// server's public IPs. If the server has no determinable public IP (e.g. behind
// NAT) it does not block ACME — it returns true with an explanatory detail.
func dnsPointsHere(domain string) (bool, string) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return false, "DNS lookup failed: " + err.Error()
	}
	local := localPublicIPs()
	if len(local) == 0 {
		return true, "could not determine this server's public IP; proceeding without the DNS check"
	}
	for _, dip := range ips {
		for _, lip := range local {
			if dip.Equal(lip) {
				return true, "matched " + dip.String()
			}
		}
	}
	return false, fmt.Sprintf("domain resolves to %v, server public IPs are %v", ips, local)
}

// localPublicIPs returns the machine's globally-routable unicast addresses (IPv4
// and IPv6), used to verify the domain points at us.
func localPublicIPs() []net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []net.IP
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
			continue
		}
		out = append(out, ip)
	}
	return out
}
