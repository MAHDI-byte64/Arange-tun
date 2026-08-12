// Package geo resolves an IP address to a country, city and network operator.
//
// It lives on its own because both the web panel and the Telegram bot need it,
// and the panel imports the bot — so the bot cannot reach back into the panel
// for it. Sharing the lookup also shares the cache, which matters: these are
// free public APIs with rate limits, and two components asking the same
// question separately is the way to get throttled.
package geo

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Info is what is known about an address.
type Info struct {
	Country string `json:"country"`
	// Code is the ISO 3166-1 alpha-2 country code, which is what a flag emoji
	// is built from. The providers all return the country name too, but a name
	// cannot be turned into a flag.
	Code string `json:"countryCode"`
	City string `json:"city"`
	ISP  string `json:"isp"`
}

// geoEntry is one cached answer. A nil info is a real answer too — "asked, and
// nobody knew" — which is why it is stored rather than discarded; see Lookup.
type geoEntry struct {
	info *Info
	exp  time.Time
}

var (
	geoCache = map[string]geoEntry{}
	geoMu    sync.Mutex
)

// How long an answer stands. A location is close to immutable, so a hit is kept
// for hours. A miss is not an answer about the address, it is an answer about
// the network — every provider was unreachable — so it is retried far sooner,
// while still being remembered long enough to matter.
const (
	geoHitTTL  = 6 * time.Hour
	geoMissTTL = 15 * time.Minute
	// geoMaxEntries bounds the map. The key space is the addresses this node's
	// tunnels talk to, which is small, but a server tunnel sees whatever dials
	// it — so it needs a ceiling rather than trust.
	geoMaxEntries = 1024
)

// geoProviders is an ordered list of lookup functions. The first that succeeds
// wins. Multiple providers are tried because any single one may be blocked from
// some networks such as Iran.
//
// Every one of them is HTTPS, and that is a requirement rather than a
// preference. The addresses looked up here are the far ends of this node's
// tunnels, and the panel asks about them continuously. Over plain HTTP that is
// a running, in-the-clear announcement — to the one network the tunnels exist
// to get past — of exactly which foreign servers this machine talks to. The
// query is not secret to the provider, but it must not be readable by everyone
// carrying the packet.
var geoProviders = []func(string) *Info{geoFromIpwho, geoFromIpSb, geoFromIpApiCo}

// Lookup resolves an IP, caching the answer. It returns nil when nothing is
// known, which callers must treat as "unavailable" rather than an error.
//
// Failures are cached as well as successes. Without that, an address no
// provider can answer for is re-asked on every single call — and the caller is
// the panel's tunnel list, which rebuilds every few seconds. On a network where
// all the providers are blocked, which is the normal case for the machines this
// runs on, that turned one panel refresh into three connection attempts per
// tunnel, each waiting out its own timeout, forever.
func Lookup(ip string) *Info {
	if ip == "" || ip == "-" {
		return nil
	}
	now := time.Now()
	geoMu.Lock()
	if e, ok := geoCache[ip]; ok && now.Before(e.exp) {
		geoMu.Unlock()
		return e.info
	}
	geoMu.Unlock()

	var found *Info
	for _, provider := range geoProviders {
		if g := provider(ip); g != nil && (g.Country != "" || g.ISP != "") {
			found = g
			break
		}
	}

	ttl := geoMissTTL
	if found != nil {
		ttl = geoHitTTL
	}
	geoMu.Lock()
	geoCache[ip] = geoEntry{info: found, exp: time.Now().Add(ttl)}
	if len(geoCache) > geoMaxEntries {
		sweepLocked()
	}
	geoMu.Unlock()
	return found
}

// sweepLocked drops expired entries, and if that was not enough — every entry
// still live — empties the map rather than let it grow past the ceiling. The
// caller must hold geoMu.
func sweepLocked() {
	now := time.Now()
	for k, e := range geoCache {
		if now.After(e.exp) {
			delete(geoCache, k)
		}
	}
	if len(geoCache) > geoMaxEntries {
		geoCache = map[string]geoEntry{}
	}
}

// geoGetter performs the request behind every provider. It is a variable so a
// test can see what the providers ask for without reaching the network.
var geoGetter = geoGet

func geoGet(url string, out any) bool {
	client := &http.Client{Timeout: 6 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	return json.NewDecoder(resp.Body).Decode(out) == nil
}

// geoFromIpwho — ipwho.is (HTTPS, no key).
func geoFromIpwho(ip string) *Info {
	var r struct {
		Success     bool   `json:"success"`
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
		City        string `json:"city"`
		Connection  struct {
			ISP string `json:"isp"`
			Org string `json:"org"`
		} `json:"connection"`
	}
	if geoGetter("https://ipwho.is/"+url.PathEscape(ip), &r) && r.Success {
		isp := r.Connection.ISP
		if isp == "" {
			isp = r.Connection.Org
		}
		return &Info{Country: r.Country, Code: r.CountryCode, City: r.City, ISP: isp}
	}
	return nil
}

// geoFromIpSb — api.ip.sb (HTTPS, no key).
func geoFromIpSb(ip string) *Info {
	var r struct {
		Country      string `json:"country"`
		CountryCode  string `json:"country_code"`
		City         string `json:"city"`
		ISP          string `json:"isp"`
		Organization string `json:"organization"`
	}
	if geoGetter("https://api.ip.sb/geoip/"+url.PathEscape(ip), &r) && r.Country != "" {
		isp := r.ISP
		if isp == "" {
			isp = r.Organization
		}
		return &Info{Country: r.Country, Code: r.CountryCode, City: r.City, ISP: isp}
	}
	return nil
}

// geoFromIpApiCo — ipapi.co (HTTPS, no key). Third in line, so it is only asked
// when the other two are unreachable; it replaces the plaintext ip-api.com that
// used to hold this slot.
func geoFromIpApiCo(ip string) *Info {
	var r struct {
		City        string `json:"city"`
		Country     string `json:"country_name"`
		CountryCode string `json:"country_code"`
		Org         string `json:"org"`
		Error       bool   `json:"error"`
	}
	if geoGetter("https://ipapi.co/"+url.PathEscape(ip)+"/json/", &r) && !r.Error && r.Country != "" {
		return &Info{Country: r.Country, Code: r.CountryCode, City: r.City, ISP: r.Org}
	}
	return nil
}
