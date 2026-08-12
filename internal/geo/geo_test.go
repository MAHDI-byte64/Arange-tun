package geo

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// resetCache empties the shared cache so one test cannot see another's answers.
func resetCache(t *testing.T) {
	t.Helper()
	geoMu.Lock()
	geoCache = map[string]geoEntry{}
	geoMu.Unlock()
}

// withProviders swaps the provider list for the duration of a test.
func withProviders(t *testing.T, p ...func(string) *Info) {
	t.Helper()
	saved := geoProviders
	geoProviders = p
	t.Cleanup(func() { geoProviders = saved })
}

func TestLookupCachesAHit(t *testing.T) {
	resetCache(t)
	calls := 0
	withProviders(t, func(string) *Info {
		calls++
		return &Info{Country: "Germany", Code: "DE"}
	})

	for i := 0; i < 5; i++ {
		if g := Lookup("192.0.2.1"); g == nil || g.Code != "DE" {
			t.Fatalf("lookup %d returned %v", i, g)
		}
	}
	if calls != 1 {
		t.Fatalf("provider called %d times for one address, want 1", calls)
	}
}

// The reason this matters: the panel's tunnel list calls Lookup for every peer
// on every refresh, a few seconds apart. On a network where the providers are
// blocked — which is the normal case for the servers this runs on — an
// uncached miss meant every one of those refreshes opened a fresh connection
// per provider and waited out its timeout, forever.
func TestLookupCachesAMiss(t *testing.T) {
	resetCache(t)
	calls := 0
	withProviders(t, func(string) *Info {
		calls++
		return nil
	})

	for i := 0; i < 5; i++ {
		if g := Lookup("192.0.2.2"); g != nil {
			t.Fatalf("lookup %d returned %v, want nil", i, g)
		}
	}
	if calls != 1 {
		t.Fatalf("provider called %d times for one unanswerable address, want 1", calls)
	}
}

// A miss is a statement about the network, not about the address, so it has to
// be retried far sooner than a hit — otherwise a panel that started up while
// the link was down shows no locations for the rest of the day.
func TestAMissIsRetriedSoonerThanAHitIsRefreshed(t *testing.T) {
	if geoMissTTL >= geoHitTTL {
		t.Fatalf("miss TTL %v is not shorter than hit TTL %v", geoMissTTL, geoHitTTL)
	}

	resetCache(t)
	calls := 0
	withProviders(t, func(string) *Info {
		calls++
		return nil
	})

	Lookup("192.0.2.3")
	// Age the entry past the miss TTL, as a quiet quarter of an hour would.
	geoMu.Lock()
	e := geoCache["192.0.2.3"]
	e.exp = time.Now().Add(-time.Second)
	geoCache["192.0.2.3"] = e
	geoMu.Unlock()

	Lookup("192.0.2.3")
	if calls != 2 {
		t.Fatalf("provider called %d times, want 2 — the lapsed miss was not retried", calls)
	}
}

// A server tunnel is dialled by whoever finds it, so the addresses asked about
// are not bounded by anything this machine controls.
func TestCacheDoesNotGrowWithoutBound(t *testing.T) {
	resetCache(t)
	withProviders(t, func(string) *Info { return nil })

	for i := 0; i < geoMaxEntries*2; i++ {
		Lookup(fmt.Sprintf("198.51.100.%d.%d", i/256, i%256))
	}

	geoMu.Lock()
	n := len(geoCache)
	geoMu.Unlock()
	if n > geoMaxEntries {
		t.Fatalf("cache holds %d entries, past the %d ceiling", n, geoMaxEntries)
	}
}

func TestLookupTriesEveryProviderUntilOneAnswers(t *testing.T) {
	resetCache(t)
	withProviders(t,
		func(string) *Info { return nil },
		func(string) *Info { return &Info{} }, // answered, but knows nothing
		func(string) *Info { return &Info{Country: "Sweden", Code: "SE"} },
	)

	g := Lookup("192.0.2.4")
	if g == nil || g.Code != "SE" {
		t.Fatalf("Lookup = %v, want the third provider's answer", g)
	}
}

// Everything these providers are asked travels over the network the tunnels
// exist to get past, and what is asked is the address of the far end of a
// tunnel. Over plain HTTP that is an in-the-clear announcement, repeated every
// few seconds, of exactly which foreign servers this machine talks to.
func TestEveryProviderIsHTTPS(t *testing.T) {
	var seen []string

	// Capture the URL each provider builds without letting it reach the wire.
	restore := geoGetter
	t.Cleanup(func() { geoGetter = restore })
	geoGetter = func(url string, _ any) bool {
		seen = append(seen, url)
		return false
	}
	for _, p := range geoProviders {
		p("192.0.2.5")
	}

	if len(seen) != len(geoProviders) {
		t.Fatalf("captured %d URLs from %d providers", len(seen), len(geoProviders))
	}
	for _, u := range seen {
		if !strings.HasPrefix(u, "https://") {
			t.Errorf("provider queries %q in the clear", u)
		}
	}
}
