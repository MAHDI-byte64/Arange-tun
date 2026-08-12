package webui

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// Compression, because of where these panels are reached from.
//
// The dashboard is a single self-contained page of about 270 KB — markup, CSS
// and script in one file — and it was sent uncompressed on every load. It is
// almost entirely text, so it packs down by roughly five to one; over the sort
// of link an Iranian VPS is administered across, that is the difference between
// a page that appears and one that visibly loads. The JSON endpoints matter for
// a different reason: they are small individually but polled every few seconds
// for as long as the tab is open, so the saving is continuous.
//
// The page is compressed once at startup rather than per request — it never
// changes — while the API responses are compressed as they are written.

// gzipMinSize is the response size below which compressing is not worth it: the
// gzip header and trailer are about 20 bytes, and a short JSON reply ("status":
// "ok") comes out no smaller and sometimes larger.
const gzipMinSize = 512

// clientAcceptsGzip reports whether the browser said it could decode gzip.
func clientAcceptsGzip(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept-Encoding"), "gzip")
}

// gzipBytes compresses b at the default level.
func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		return nil
	}
	if err := zw.Close(); err != nil {
		return nil
	}
	return buf.Bytes()
}

// servePrecompressed writes body, using a gzipped copy when the client accepts
// one. The compressed copy is built on first use and kept, so a page that never
// changes is only ever compressed once however many times it is loaded.
func servePrecompressed(w http.ResponseWriter, r *http.Request, contentType string, body []byte, cache *precompressed) {
	w.Header().Set("Content-Type", contentType)
	if !clientAcceptsGzip(r) || len(body) < gzipMinSize {
		w.Write(body)
		return
	}
	packed := cache.get(body)
	if packed == nil { // compression failed — send it plain rather than nothing
		w.Write(body)
		return
	}
	// Vary matters even on a panel with no proxy in front of it: without it a
	// cache between the browser and here could hand the gzipped copy to a
	// client that never asked for one.
	w.Header().Set("Vary", "Accept-Encoding")
	w.Header().Set("Content-Encoding", "gzip")
	w.Write(packed)
}

// precompressed holds the gzipped form of a fixed body.
type precompressed struct {
	once sync.Once
	data []byte
}

func (p *precompressed) get(body []byte) []byte {
	p.once.Do(func() { p.data = gzipBytes(body) })
	return p.data
}

var (
	dashboardGz precompressed
	loginGz     precompressed
)

// gzipMiddleware compresses every response the panel produces that is worth
// compressing.
//
// It buffers the response and decides at the end, which is only safe because
// nothing here streams: there is no server-sent-events endpoint, no handler
// that flushes progressively, and no connection hijacking. Buffering keeps the
// handlers themselves untouched — the panel writes JSON from more than fifty
// places, and none of them has to know about this.
func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !clientAcceptsGzip(r) {
			next.ServeHTTP(w, r)
			return
		}
		buf := &bufferingWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(buf, r)
		buf.finish()
	})
}

// bufferingWriter collects a handler's output so it can be compressed once the
// whole body — and therefore its size and type — is known.
type bufferingWriter struct {
	http.ResponseWriter
	body   bytes.Buffer
	status int
	// wroteHeader records that the handler chose a status, so finish sends
	// that one rather than a default 200.
	wroteHeader bool
}

func (b *bufferingWriter) WriteHeader(status int) {
	if !b.wroteHeader {
		b.status, b.wroteHeader = status, true
	}
}

func (b *bufferingWriter) Write(p []byte) (int, error) {
	return b.body.Write(p)
}

// finish sends what the handler produced, gzipped when that helps.
func (b *bufferingWriter) finish() {
	body := b.body.Bytes()
	h := b.Header()

	// Leave alone anything already encoded (a pre-compressed page) or already
	// in a compressed format (the settings backup is a .tar.gz): packing those
	// again costs CPU and saves nothing.
	if len(body) < gzipMinSize || h.Get("Content-Encoding") != "" || alreadyCompressed(h.Get("Content-Type")) {
		b.send(body, false)
		return
	}
	packed := gzipBytes(body)
	if packed == nil || len(packed) >= len(body) {
		b.send(body, false)
		return
	}
	b.send(packed, true)
}

func (b *bufferingWriter) send(body []byte, gzipped bool) {
	h := b.Header()
	if gzipped {
		h.Set("Content-Encoding", "gzip")
		h.Set("Vary", "Accept-Encoding")
	}
	// Set explicitly: the length was not known when the handler ran, and a
	// stale one from before compression would truncate the response.
	h.Set("Content-Length", strconv.Itoa(len(body)))
	b.ResponseWriter.WriteHeader(b.status)
	b.ResponseWriter.Write(body)
}

// alreadyCompressed reports whether a content type carries its own compression.
func alreadyCompressed(contentType string) bool {
	ct := strings.ToLower(contentType)
	for _, p := range []string{"application/gzip", "application/zip", "application/x-gzip", "image/", "video/", "audio/"} {
		if strings.HasPrefix(ct, p) {
			return true
		}
	}
	return false
}
