package tlscert

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadOrCreate(t *testing.T) {
	dir := t.TempDir()

	c1, err := LoadOrCreate(dir, "example-host")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c1.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "example-host" {
		t.Fatalf("CN = %q", leaf.Subject.CommonName)
	}
	// ~10 year validity.
	got := time.Until(leaf.NotAfter)
	if got < 9*365*24*time.Hour || got > 11*365*24*time.Hour {
		t.Fatalf("validity = %v, want ~10y", got)
	}

	// Key file must be 0600.
	info, err := os.Stat(filepath.Join(dir, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("key perm = %o, want 0600", perm)
	}

	// Second call loads the SAME cert (idempotent, no regeneration).
	c2, err := LoadOrCreate(dir, "example-host")
	if err != nil {
		t.Fatal(err)
	}
	fp1, _ := LeafFingerprint(&c1)
	fp2, _ := LeafFingerprint(&c2)
	if fp1 != fp2 {
		t.Fatal("cert regenerated on second load (fingerprint changed)")
	}
}

func TestFingerprintDeterministic(t *testing.T) {
	der := []byte("some-der-bytes")
	if Fingerprint(der) != Fingerprint(der) {
		t.Fatal("fingerprint not deterministic")
	}
	if Fingerprint(der) == Fingerprint([]byte("other")) {
		t.Fatal("distinct inputs share a fingerprint")
	}
}

func TestDefaultServerName(t *testing.T) {
	dir := t.TempDir()
	c, err := LoadOrCreate(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(c.Certificate[0])
	if leaf.Subject.CommonName != "localhost" {
		t.Fatalf("default CN = %q, want localhost", leaf.Subject.CommonName)
	}
}
