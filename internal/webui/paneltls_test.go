package webui

import (
	"net/http"
	"testing"
)

// The panel can serve HTTPS, and the choice has to survive an upgrade without
// moving anyone's bookmark.

// Plain HTTP is the default and stays the default: a config written before any
// of this existed has no https key at all, and a panel that quietly switched
// scheme on update would be unreachable at the address people use.
func TestPanelStaysOnPlainHTTPUnlessAsked(t *testing.T) {
	var c Config // what an older config decodes to
	if c.HTTPS {
		t.Error("HTTPS is on by default; an upgrade would move the panel's address")
	}
	if got := c.Scheme(); got != "http" {
		t.Errorf("scheme = %q, want http", got)
	}
}

func TestSchemeFollowsTheSetting(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want string
	}{
		{"off", Config{}, "http"},
		{"self-signed", Config{HTTPS: true}, "https"},
		{"lets encrypt", Config{HTTPS: true, TLSDomain: "panel.example.com"}, "https"},
		// A domain without HTTPS is not a half-on state: the switch is what
		// decides, so a leftover domain cannot silently turn TLS on.
		{"domain but disabled", Config{TLSDomain: "panel.example.com"}, "http"},
	} {
		if got := tc.cfg.Scheme(); got != tc.want {
			t.Errorf("%s: scheme = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The session cookie is what stands between the internet and a panel that can
// build and delete tunnels, so on a panel serving TLS it must never be sent
// back in the clear.
func TestSessionCookieIsSecureOnlyWhenThePanelIsHTTPS(t *testing.T) {
	for _, tc := range []struct {
		name  string
		https bool
	}{
		{"plain http", false},
		{"https", true},
	} {
		c := sessionCookieFor("deadbeef", tc.https)
		if c.Secure != tc.https {
			t.Errorf("%s: Secure = %v, want %v", tc.name, c.Secure, tc.https)
		}
		// These two hold either way: the token is not for scripts to read, and
		// a cross-site POST must not carry it.
		if !c.HttpOnly {
			t.Errorf("%s: the session cookie is readable from JavaScript", tc.name)
		}
		if c.SameSite == http.SameSiteNoneMode || c.SameSite == 0 {
			t.Errorf("%s: SameSite = %v, want Lax or stricter", tc.name, c.SameSite)
		}
	}
}

// Turning Secure on unconditionally would be the obvious "safer" choice and
// would lock out every existing install: a panel on http:// would set a cookie
// the browser then refuses to send back, so the login would appear to succeed
// and land straight back on the login page.
func TestAPlainHTTPPanelStillGetsAUsableCookie(t *testing.T) {
	if sessionCookieFor("deadbeef", false).Secure {
		t.Fatal("a plain-HTTP panel issued a Secure cookie; nobody could log in")
	}
}
