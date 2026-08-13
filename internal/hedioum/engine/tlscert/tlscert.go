// Package tlscert generates and loads the foreign node's self-signed TLS
// certificate for the TLS mimic. No domain and no CA are involved: the cert is
// only camouflage (it makes the link look like HTTPS). Authentication is the
// pre-shared token, bound to this cert's fingerprint (see the TLS mimic), so a
// captured or swapped cert cannot forge or inject into the tunnel.
package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	certFile = "cert.pem"
	keyFile  = "key.pem"
	validFor = 10 * 365 * 24 * time.Hour // 10 years
)

// LoadOrCreate loads the cert+key from dir, or generates a fresh self-signed
// 10-year ECDSA P-256 certificate (CN/SAN = serverName, default "localhost") if
// either file is missing/unreadable. The key is written 0600.
func LoadOrCreate(dir, serverName string) (tls.Certificate, error) {
	if serverName == "" {
		serverName = "localhost"
	}
	certPath := filepath.Join(dir, certFile)
	keyPath := filepath.Join(dir, keyFile)

	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return c, nil
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return tls.Certificate{}, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: serverName},
		DNSNames:              []string{serverName},
		NotBefore:             time.Now().Add(-1 * time.Hour), // tolerate clock skew
		NotAfter:              time.Now().Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return tls.Certificate{}, err
	}

	return tls.LoadX509KeyPair(certPath, keyPath)
}

// Fingerprint returns the SHA-256 of the certificate's DER encoding — the value
// both sides bind the token auth to (channel binding).
func Fingerprint(der []byte) [32]byte {
	return sha256.Sum256(der)
}

// LeafFingerprint returns the fingerprint of a parsed/loaded tls.Certificate's
// leaf.
func LeafFingerprint(c *tls.Certificate) ([32]byte, error) {
	if len(c.Certificate) == 0 {
		return [32]byte{}, fmt.Errorf("tlscert: certificate has no leaf")
	}
	return Fingerprint(c.Certificate[0]), nil
}
