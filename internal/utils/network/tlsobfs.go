package network

// TLS obfuscation for the frp/rathole tunnels.
//
// Where the Noise stealth layer makes a connection look like nothing — a stream
// of random bytes — this makes it look like something ordinary: an HTTPS
// session. The client's ClientHello wears a current Chrome fingerprint (uTLS),
// and the server answers with a normal TLS handshake, so on the wire the tunnel
// is a TLS 1.2/1.3 flow like any other. It blends into the crowd of HTTPS rather
// than standing out as high-entropy noise, which is what some DPI systems key
// on.
//
// The certificate is self-signed and not verified: the tunnel authenticates with
// its token inside the session, exactly as the wss path does. That self-signed
// certificate is the one tell that separates this from genuine HTTPS — the
// stronger REALITY mode (which borrows a real site's certificate) is the answer
// to that, and is layered on separately.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"time"
)

var (
	selfSignedOnce sync.Once
	selfSignedCert tls.Certificate
	selfSignedErr  error
)

// selfSigned returns a process-wide self-signed certificate, generated once. It
// exists only to complete the TLS handshake; the token, not the certificate, is
// what authenticates the tunnel.
func selfSigned() (tls.Certificate, error) {
	selfSignedOnce.Do(func() {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			selfSignedErr = err
			return
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: "localhost"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().AddDate(10, 0, 0),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
		if err != nil {
			selfSignedErr = err
			return
		}
		selfSignedCert = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	})
	return selfSignedCert, selfSignedErr
}

// SelfSignedTLSConfig returns a server tls.Config backed by the process-wide
// self-signed certificate — the default when no real certificate is configured.
func SelfSignedTLSConfig() (*tls.Config, error) {
	cert, err := selfSigned()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// TLSServerConn wraps raw in a TLS server session using cfg, so the tunnel
// presents as ordinary HTTPS. cfg is built once by the caller — a self-signed
// config, or a Let's Encrypt one (ServerTLSConfig) so the certificate is real
// and the self-signed tell is gone.
func TLSServerConn(raw net.Conn, cfg *tls.Config, timeout time.Duration) (net.Conn, error) {
	tconn := tls.Server(raw, cfg)
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if err := tconn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return tconn, nil
}

// TLSClientConn wraps raw in a uTLS client session whose ClientHello mimics a
// current Chrome build, presenting serverName as the SNI (empty for a bare IP,
// like a browser). The certificate is not verified — the token authenticates the
// tunnel.
func TLSClientConn(raw net.Conn, serverName string, timeout time.Duration) (net.Conn, error) {
	uconn, err := uTLSClientConn(context.Background(), raw, serverName, timeout)
	if err != nil {
		return nil, err
	}
	return uconn, nil
}

// SNIFromAddr picks a default SNI from a host:port address: the hostname, or
// empty for a bare IP.
func SNIFromAddr(addr string) string { return sniFromAddr(addr) }
