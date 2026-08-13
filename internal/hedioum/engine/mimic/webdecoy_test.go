package mimic

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"reflect"
	"testing"
	"time"
)

// serveOnce runs a raw net.Conn decoy against an in-memory pipe and returns the
// full response bytes.
func serveOnce(t *testing.T, serve func(net.Conn)) []byte {
	t.Helper()
	c, s := net.Pipe()
	go func() {
		defer s.Close()
		serve(s)
	}()
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(c)
	return got
}

func TestServeWebDecoy(t *testing.T) {
	got := serveOnce(t, ServeWebDecoy)
	for _, want := range []string{
		"HTTP/1.1 200 OK", "Server: Apache/2.4.", "It works", "Apache2 Ubuntu Default Page",
		"ETag: \"", "Last-Modified: ", "Accept-Ranges: bytes", "GMT",
	} {
		if !bytes.Contains(got, []byte(want)) {
			t.Fatalf("apache decoy missing %q in: %q", want, got)
		}
	}
	// HTTP dates must end in GMT, never "UTC" (a real tell).
	if bytes.Contains(got, []byte(" UTC\r\n")) {
		t.Fatalf("decoy leaked a UTC date (should be GMT): %q", got)
	}
}

// TestServeDirectAdminWeb verifies the DirectAdmin web-port default: the exact
// 47-byte body, the Apache/2 signature, and a real static-file header set.
func TestServeDirectAdminWeb(t *testing.T) {
	p := NewDecoyProfile("some-token")
	got := serveOnce(t, p.ServeDirectAdminWeb)
	for _, want := range []string{
		"HTTP/1.1 200 OK", "Server: Apache/2\r\n", "Vary: User-Agent", "Accept-Ranges: bytes",
		"ETag: \"2f-", "Last-Modified: ", "Content-Length: 47",
		"<html>webserver is functioning normally</html>",
	} {
		if !bytes.Contains(got, []byte(want)) {
			t.Fatalf("DA web decoy missing %q in: %q", want, got)
		}
	}
}

// TestWebDecoyFor maps persona styles to the right profile decoy.
func TestWebDecoyFor(t *testing.T) {
	p := NewDecoyProfile("tok")
	ptr := func(f func(net.Conn)) uintptr { return reflect.ValueOf(f).Pointer() }
	if ptr(p.WebDecoyFor("directadmin")) != ptr(p.ServeDirectAdminWeb) {
		t.Fatal("directadmin style should map to ServeDirectAdminWeb")
	}
	if ptr(p.WebDecoyFor("apache")) != ptr(p.ServeApache) {
		t.Fatal("apache style should map to ServeApache")
	}
	if ptr(p.WebDecoyFor("")) != ptr(p.ServeApache) {
		t.Fatal("empty style should fall back to ServeApache")
	}
}

// TestDecoyProfileDeterministicAndUnique: same token -> identical profile (stable per
// server); different tokens -> different aggregate identity (no fleet-wide signature);
// values stay realistic.
func TestDecoyProfileDeterministicAndUnique(t *testing.T) {
	a1 := NewDecoyProfile("token-A")
	a2 := NewDecoyProfile("token-A")
	if a1 != a2 {
		t.Fatalf("same token must yield the same profile: %+v vs %+v", a1, a2)
	}

	// Across several tokens, the (server, lastModified, etag) tuples must not collapse
	// to one value.
	seen := map[DecoyProfile]int{}
	for _, tok := range []string{"t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8"} {
		seen[NewDecoyProfile(tok)]++
	}
	if len(seen) < 5 {
		t.Fatalf("profiles not diverse enough across tokens: only %d distinct of 8", len(seen))
	}

	// Realism: the Server string is a genuine Apache-on-Ubuntu version; the
	// Last-Modified is a valid HTTP-date ending in GMT.
	p := NewDecoyProfile("realism")
	ok := false
	for _, v := range apacheVersions {
		if p.apacheServer == v {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("apacheServer %q is not a known realistic version", p.apacheServer)
	}
	if _, err := time.Parse(http.TimeFormat, p.lastModified); err != nil {
		t.Fatalf("lastModified %q is not a valid HTTP date: %v", p.lastModified, err)
	}
}
