package pool

import (
	"crypto/sha256"
	"encoding/binary"
	mrand "math/rand/v2"
	"time"
)

// Connection-lifecycle policy — the single most important stealth property.
//
// After raw data volume, the strongest real-world discriminator a censor has is
// how a connection *lives* versus what the protocol it mimics is used for: a
// "TLS"/"SMTP" flow held open for hours moving tens of GB is anomalous no matter
// how perfect its handshake. So every NON-SSH pipe is auxiliary — it retires
// after a short randomized lifetime OR a transfer budget, then the pool churns to
// a fresh pipe (reusing the Draining state so in-flight streams finish). SSH is
// the trusted long-lived backbone, but it is NOT immortal either: it rotates on a
// long randomized schedule (hours, never days/months) so no connection's age ever
// equals the process uptime.
//
// Two layers of randomness keep fingerprints from ever matching:
//   - Per-server "personality": each node's baselines are derived from a hash of
//     its (secret) auth token, so two servers churn with different aggregate
//     statistics — yet the values are unguessable from outside.
//   - Per-connection jitter: every pipe rolls a fresh unpredictable multiplier
//     around its server's baseline, so no two connections on one server match.
const (
	gib = 1 << 30

	// Non-SSH auxiliary bounds (hard clamps around the per-server baseline).
	auxMinLifetime = 5 * time.Minute
	auxMaxLifetime = 60 * time.Minute
	auxMinBudget   = 1 * gib
	auxMaxBudget   = 5 * gib

	// SSH backbone bounds — long-lived but rotating (hours, not days/months).
	sshMinLifetime = 6 * time.Hour
	sshMaxLifetime = 24 * time.Hour
)

// LifecyclePolicy holds one node's per-server baselines. It is derived once per
// node from the auth token and shared (read-only) by every session on that node's
// pools; the per-connection jitter is drawn fresh at roll() time.
type LifecyclePolicy struct {
	auxLifetimeBase time.Duration // typical non-SSH lifetime for this server
	auxBudgetBase   uint64        // typical non-SSH transfer budget for this server
	sshLifetimeBase time.Duration // typical SSH rotation interval for this server
}

// NewLifecyclePolicy derives a stable-but-unique personality for a node from a
// seed (the node's auth token). Each server lands on a different characteristic
// baseline inside the global bounds, so aggregate traffic shape differs per
// server while staying unguessable (the seed is the secret token).
func NewLifecyclePolicy(seed string) LifecyclePolicy {
	h := sha256.Sum256([]byte(seed))
	// Four independent [0,1) fractions from disjoint 8-byte windows of the hash.
	frac := func(i int) float64 {
		return float64(binary.BigEndian.Uint64(h[i:i+8])) / (1 << 64)
	}
	// Center each baseline in an INNER band of the global range so the later
	// per-connection jitter can push both up and down without immediately
	// slamming into the clamp.
	auxLife := lerpDur(frac(0), auxMinLifetime+10*time.Minute, auxMaxLifetime-15*time.Minute)
	auxBudget := lerpU64(frac(8), 2*gib, 4*gib)
	sshLife := lerpDur(frac(16), sshMinLifetime+4*time.Hour, sshMaxLifetime-6*time.Hour)

	return LifecyclePolicy{
		auxLifetimeBase: auxLife,
		auxBudgetBase:   auxBudget,
		sshLifetimeBase: sshLife,
	}
}

// roll draws this pipe's concrete retirement limits. SSH gets a long lifetime and
// no byte budget (the backbone tolerates volume); every other mimic gets a short
// lifetime and a transfer budget. A byteBudget of 0 means "no budget".
func (p LifecyclePolicy) roll(mimicType string) (retireAfter time.Duration, byteBudget uint64) {
	if mimicType == "ssh" {
		d := scaleDur(p.sshLifetimeBase, 0.5, 1.5)
		return clampDur(d, sshMinLifetime, sshMaxLifetime), 0
	}
	d := scaleDur(p.auxLifetimeBase, 0.4, 1.6)
	b := scaleU64(p.auxBudgetBase, 0.5, 1.5)
	return clampDur(d, auxMinLifetime, auxMaxLifetime), clampU64(b, auxMinBudget, auxMaxBudget)
}

// --- helpers: fresh per-call jitter (math/rand/v2 is concurrency-safe) ---

func jitter(lo, hi float64) float64 { return lo + mrand.Float64()*(hi-lo) }

func scaleDur(base time.Duration, lo, hi float64) time.Duration {
	return time.Duration(float64(base) * jitter(lo, hi))
}
func scaleU64(base uint64, lo, hi float64) uint64 {
	return uint64(float64(base) * jitter(lo, hi))
}

func lerpDur(f float64, lo, hi time.Duration) time.Duration {
	return lo + time.Duration(f*float64(hi-lo))
}
func lerpU64(f float64, lo, hi uint64) uint64 {
	return lo + uint64(f*float64(hi-lo))
}

func clampDur(v, lo, hi time.Duration) time.Duration {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
func clampU64(v, lo, hi uint64) uint64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
