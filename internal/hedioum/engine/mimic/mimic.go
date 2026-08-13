// Package mimic provides pluggable camouflage layers. Every mimic disguises the
// tunnel as a different well-known protocol on the wire and, for unauthenticated
// peers (scanners/probes/browsers), forwards them to a believable decoy backend
// so the port is indistinguishable from a real service.
//
// The shape is uniform across mimics:
//
//	[ camouflage handshake ] -> [ single-layer auth+crypto ] -> [ yamux tunnel ]
//	         |                              |
//	         |                              +-- auth fails -> replay to Decoy()
//	         +-- SSH: banner exchange (+ securestream)
//	             TLS: real TLS (+ channel-bound token auth)   [added later]
//
// Each mimic yields an authenticated, encrypted net.Conn with exactly ONE crypto
// layer, so a pool mixing several mimics has uniform performance.
package mimic

import "net"

// ServerMimic performs the server side of a camouflage handshake.
type ServerMimic interface {
	// Accept runs the full server handshake (camouflage + auth) on an accepted
	// conn. On success it returns an authenticated, encrypted net.Conn ready for
	// yamux. On failure it returns an error (securestream.ErrAuth for a wrong/
	// missing credential) together with a replay net.Conn carrying the exact bytes
	// the peer sent, so the caller can forward the probe to Decoy().
	Accept(conn net.Conn) (authed net.Conn, replay net.Conn, err error)
	// ProxyDecoy forwards an unauthenticated peer (the replay conn from a failed
	// Accept) to this mimic's decoy backend, in a protocol-appropriate way (e.g.
	// the SSH mimic consumes the real sshd banner to avoid a double banner). It
	// takes ownership of replay and closes it.
	ProxyDecoy(replay net.Conn)
	// Name is the mimic's protocol label (e.g. "ssh", "tls").
	Name() string
}

// ClientMimic performs the client side of a camouflage handshake.
type ClientMimic interface {
	// Dial runs the full client handshake on a freshly-dialed conn and returns an
	// authenticated, encrypted net.Conn ready for yamux.
	Dial(conn net.Conn) (authed net.Conn, err error)
	// Name is the mimic's protocol label.
	Name() string
}
