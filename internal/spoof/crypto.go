package spoof

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// aead wraps a ChaCha20-Poly1305 cipher keyed by a shared secret. Every sealed
// frame carries its own random nonce as a prefix, so the two ends never have to
// agree a nonce sequence — which suits a lossy, reordered, spoofed datagram
// path where any packet can vanish.
type aead struct {
	c interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
		NonceSize() int
		Overhead() int
	}
}

// newAEAD derives a 32-byte key from the shared secret and builds the cipher.
func newAEAD(secret string) (*aead, error) {
	if secret == "" {
		return nil, fmt.Errorf("a shared key is required")
	}
	key := sha256.Sum256([]byte("arange-tun/spoof\x00" + secret))
	c, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return &aead{c: c}, nil
}

// seal encrypts a payload into a self-contained frame: nonce ‖ ciphertext‖tag.
func (a *aead) seal(payload []byte) ([]byte, error) {
	nonce := make([]byte, a.c.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, len(nonce), len(nonce)+len(payload)+a.c.Overhead())
	copy(out, nonce)
	return a.c.Seal(out, nonce, payload, nil), nil
}

// open reverses seal. A frame that is too short or fails authentication is
// rejected — which is also how a spoofed-path receiver drops the stray packets
// that the raw filter let through but that were not ours.
func (a *aead) open(frame []byte) ([]byte, error) {
	ns := a.c.NonceSize()
	if len(frame) < ns+a.c.Overhead() {
		return nil, fmt.Errorf("frame too short")
	}
	return a.c.Open(nil, frame[:ns], frame[ns:], nil)
}
