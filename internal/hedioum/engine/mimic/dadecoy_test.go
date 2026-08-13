package mimic

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// daRequest drives one HTTP/1.1 request through ServeDirectAdminPanel over an
// in-memory pipe and returns the raw response.
func daRequest(t *testing.T, reqLine string) string {
	t.Helper()
	c, s := net.Pipe()
	go func() {
		ServeDirectAdminPanel(s)
		s.Close()
	}()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	go func() {
		_, _ = c.Write([]byte(reqLine + " HTTP/1.1\r\nHost: panel\r\nConnection: close\r\n\r\n"))
	}()
	body, _ := io.ReadAll(c)
	c.Close()
	return string(body)
}

// TestDirectAdminRootRedirect: "/" 302-redirects to /evo/, exactly like a real panel.
func TestDirectAdminRootRedirect(t *testing.T) {
	got := daRequest(t, "GET /")
	for _, want := range []string{"302 Found", "Location: /evo/", "X-Frame-Options: sameorigin"} {
		if !strings.Contains(got, want) {
			t.Fatalf("root redirect missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Server:") {
		t.Fatalf("must not send a Server header:\n%s", got)
	}
}

// TestDirectAdminLoginPage: /evo/login serves the rendered Evolution login with the
// real class names, field placeholders, branding assets, and DA headers.
func TestDirectAdminLoginPage(t *testing.T) {
	got := daRequest(t, "GET /evo/login")
	for _, want := range []string{
		"200 OK",
		"| Login</title>",
		`class="Box__Form"`,
		"Please enter username",
		"Please enter your password",
		"Sign in",
		"/evo/assets/logo.fe968txS.svg",
		"/evo/assets/logo2.AfEZecTW.svg", // dark-mode logo
		"/evo/assets/background.Cx34YJbp.svg",
		"/evo/assets/background-dark.BawLIQ0N.svg",     // dark-mode background
		"prefers-color-scheme: dark",                   // light + dark support
		"Hmm, login details do not seem to be correct", // real panel error text
		"X-Frame-Options: sameorigin",
		"X-Content-Type-Options: nosniff",
		"Cache-Control: no-cache",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("login page missing %q:\n%.400s", want, got)
		}
	}
	if strings.Contains(got, "Server:") {
		t.Fatalf("login page must not send a Server header")
	}
}

// TestDirectAdminAssets: the branding assets are served with the right content type.
func TestDirectAdminAssets(t *testing.T) {
	cases := []struct{ req, ct string }{
		{"GET /evo/assets/logo.fe968txS.svg", "image/svg+xml"},
		{"GET /evo/assets/logo2.AfEZecTW.svg", "image/svg+xml"},
		{"GET /evo/assets/background.Cx34YJbp.svg", "image/svg+xml"},
		{"GET /evo/assets/background-dark.BawLIQ0N.svg", "image/svg+xml"},
		{"GET /evo/assets/favicon.CDLA4ANV.png", "image/png"},
	}
	for _, c := range cases {
		got := daRequest(t, c.req)
		if !strings.Contains(got, "200 OK") || !strings.Contains(got, "Content-Type: "+c.ct) {
			t.Fatalf("%s: want 200 %s, got:\n%.200s", c.req, c.ct, got)
		}
		if !strings.Contains(got, "immutable") {
			t.Fatalf("%s: assets should be cacheable/immutable", c.req)
		}
	}
}

// TestDirectAdminAPIInfo: /api/info reports a healthy (active) license as JSON.
func TestDirectAdminAPIInfo(t *testing.T) {
	got := daRequest(t, "GET /api/info")
	for _, want := range []string{"200 OK", "application/json", `"license":{"active":true}`} {
		if !strings.Contains(got, want) {
			t.Fatalf("/api/info missing %q:\n%s", want, got)
		}
	}
}

// TestDirectAdminLogin: a login attempt is answered like a real bad login (401),
// never accepted — the decoy stores/forwards nothing.
func TestDirectAdminLogin(t *testing.T) {
	got := daRequest(t, "POST /api/login")
	if !strings.Contains(got, "401") || !strings.Contains(got, "Invalid credentials") {
		t.Fatalf("login should be rejected like a real panel:\n%s", got)
	}
}
