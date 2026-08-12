package webui

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// Compression sits in front of every response the panel sends, so a mistake
// here breaks the whole panel rather than one endpoint. What has to hold: the
// bytes survive the round trip unchanged, the status the handler chose is the
// status the client sees, and Content-Length describes what was actually sent —
// a stale one truncates the response.

// serveThrough runs body through the middleware and returns the recorded reply.
func serveThrough(t *testing.T, acceptGzip bool, h http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if acceptGzip {
		req.Header.Set("Accept-Encoding", "gzip")
	}
	rec := httptest.NewRecorder()
	gzipMiddleware(h).ServeHTTP(rec, req)
	return rec
}

// bigJSON is comfortably over gzipMinSize and compresses well, like the real
// tunnel list.
func bigJSON() string {
	return `{"tunnels":[` + strings.Repeat(`{"name":"tunnel","state":"online"},`, 200) + `]}`
}

func TestLargeResponseIsGzippedAndDecodesBackUnchanged(t *testing.T) {
	want := bigJSON()
	rec := serveThrough(t, true, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, want)
	})

	if enc := rec.Header().Get("Content-Encoding"); enc != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", enc)
	}
	if v := rec.Header().Get("Vary"); !strings.Contains(v, "Accept-Encoding") {
		t.Errorf("Vary = %q, want it to mention Accept-Encoding", v)
	}
	if rec.Body.Len() >= len(want) {
		t.Errorf("compressed to %d bytes from %d — no saving", rec.Body.Len(), len(want))
	}

	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("the body is not valid gzip: %v", err)
	}
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if string(got) != want {
		t.Error("the response did not survive the round trip unchanged")
	}
}

// The middleware sets Content-Length itself, because the size is only known
// after compressing. It has to describe the compressed body: a length left over
// from the uncompressed one would truncate the reply.
//
// Only the compressed path is checked here — a client that cannot take gzip is
// passed straight to the underlying writer, and net/http fills the length in.
func TestContentLengthMatchesTheCompressedBody(t *testing.T) {
	rec := serveThrough(t, true, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, bigJSON())
	})
	declared, err := strconv.Atoi(rec.Header().Get("Content-Length"))
	if err != nil {
		t.Fatalf("Content-Length is not a number: %v", err)
	}
	if declared != rec.Body.Len() {
		t.Errorf("Content-Length says %d, body is %d — the reply would be truncated",
			declared, rec.Body.Len())
	}
}

func TestAClientThatCannotDecodeGzipGetsPlainBytes(t *testing.T) {
	want := bigJSON()
	rec := serveThrough(t, false, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, want)
	})
	if enc := rec.Header().Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding = %q for a client that did not ask for it", enc)
	}
	if rec.Body.String() != want {
		t.Error("the plain response was altered")
	}
}

// Compressing a short reply makes it bigger, and costs a round of CPU to do it.
func TestSmallResponseIsLeftAlone(t *testing.T) {
	rec := serveThrough(t, true, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"status":"ok"}`)
	})
	if enc := rec.Header().Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding = %q on a tiny reply", enc)
	}
	if rec.Body.String() != `{"status":"ok"}` {
		t.Errorf("body = %q", rec.Body.String())
	}
}

// The status a handler chose must reach the client — an unauthorised reply that
// arrives as 200 would let the page treat a rejection as success.
func TestHandlerStatusIsPreserved(t *testing.T) {
	rec := serveThrough(t, true, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, strings.Repeat("<p>denied</p>", 100))
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// The settings backup is a .tar.gz; packing it again wastes CPU for nothing.
func TestAlreadyCompressedContentIsNotPackedAgain(t *testing.T) {
	rec := serveThrough(t, true, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Write([]byte(strings.Repeat("\x00\x01\x02\x03", 400)))
	})
	if enc := rec.Header().Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding = %q on an archive download", enc)
	}
}

// A handler that compressed for itself (the pre-compressed dashboard) must not
// be compressed a second time, which no browser would unpack twice.
func TestAPreCompressedResponsePassesThrough(t *testing.T) {
	payload := gzipBytes([]byte(bigJSON()))
	rec := serveThrough(t, true, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(payload)
	})
	if rec.Body.Len() != len(payload) {
		t.Fatalf("body is %d bytes, want the handler's own %d — it was packed twice", rec.Body.Len(), len(payload))
	}
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("not valid gzip: %v", err)
	}
	if _, err := io.ReadAll(zr); err != nil {
		t.Errorf("the handler's own compression was disturbed: %v", err)
	}
}

// The dashboard is the reason this exists: one 270 KB page of text, sent on
// every load over a link that is often slow.
func TestTheDashboardIsWorthCompressing(t *testing.T) {
	packed := gzipBytes(dashboardHTML)
	if packed == nil {
		t.Fatal("the dashboard would not compress")
	}
	ratio := float64(len(packed)) / float64(len(dashboardHTML))
	if ratio > 0.5 {
		t.Errorf("compressed to %.0f%% of %d bytes — expected far better on a page of text",
			ratio*100, len(dashboardHTML))
	}
	t.Logf("dashboard: %d bytes -> %d gzipped (%.0f%%)", len(dashboardHTML), len(packed), ratio*100)
}
