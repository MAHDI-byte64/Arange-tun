package mimic

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"time"
)

// apacheDefaultPage mirrors the recognizable Apache2 Ubuntu "Default Page" so a
// probe or a person hitting the port sees exactly what a freshly-installed Apache
// on Ubuntu serves — nothing tunnel-specific. Trimmed but faithful to the real
// page's title, banner, and wording.
const apacheDefaultPage = `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en">
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Apache2 Ubuntu Default Page: It works</title>
    <style type="text/css">
      * { margin: 0px 0px 0px 0px; padding: 0px 0px 0px 0px; }
      body, html { padding: 3px 3px 3px 3px; background-color: #D8DBE2; font-family: Verdana, sans-serif; font-size: 11pt; text-align: center; }
      div.main_page { position: relative; display: table; width: 800px; margin-bottom: 3px; margin-left: auto; margin-right: auto; padding: 0px; border-width: 2px; border-color: #212738; border-style: solid; background-color: #FFFFFF; text-align: center; }
      div.page_header { height: 99px; width: 100%; background-color: #F5F6F7; }
      div.page_header span { margin: 15px 0px 0px 50px; font-size: 180%; font-weight: bold; }
      div.table_of_contents { clear: left; min-width: 200px; margin: 3px 3px 3px 3px; background-color: #FFFFFF; text-align: left; }
      div.content_section { margin: 3px 3px 3px 3px; background-color: #FFFFFF; text-align: left; }
      div.content_section_text { padding: 4px 8px 4px 8px; color: #000000; font-size: 100%; }
      div.content_section_text a { color: #000000; font-weight: bold; }
      div.validator {}
    </style>
  </head>
  <body>
    <div class="main_page">
      <div class="page_header floating_element">
        <span class="floating_element">Apache2 Ubuntu Default Page</span>
      </div>
      <div class="content_section floating_element">
        <div class="content_section_text">
          <p><span style="font-size: 130%; font-weight: bold;">It works!</span></p>
          <p>This is the default welcome page used to test the correct operation of the Apache2 server after installation on Ubuntu systems. It is based on the equivalent page on Debian, from which the Ubuntu Apache packaging is derived. If you can read this page, it means that the Apache HTTP server installed at this site is working properly. You should <b>replace this file</b> (located at <tt>/var/www/html/index.html</tt>) before continuing to operate your HTTP server.</p>
          <p>If you are a normal user of this web site and don't know what this page is about, this probably means that the site is currently unavailable due to maintenance. If the problem persists, please contact the site's administrator.</p>
        </div>
      </div>
    </div>
    <div class="validator"></div>
  </body>
</html>`

// daWebDefault is exactly what a real DirectAdmin box serves on its web ports
// (:80/:443) when hit without the panel port — a 47-byte static file. Captured
// verbatim from a live DirectAdmin server.
const daWebDefault = "<html>webserver is functioning normally</html>\n"

// DecoyProfile is the per-install-stable identity of the web decoy. The response a
// static-file web server sends is otherwise byte-identical across every Hedioum
// node — a fleet-wide signature. This derives a realistic-but-unique server version,
// Last-Modified date and ETag suffix from the node's (secret) auth token, so no two
// installs share the same values, while any single node stays stable over time.
type DecoyProfile struct {
	apacheServer string // "Apache/2.4.xx (Ubuntu)"
	lastModified string // RFC1123-GMT
	etagSuffix   string // hex, per-install (second half of the ETag)
}

// apacheVersions are all real Apache-on-Ubuntu Server strings (distro packages), so
// a chosen value never looks synthetic.
var apacheVersions = []string{
	"Apache/2.4.52 (Ubuntu)", // 22.04
	"Apache/2.4.58 (Ubuntu)", // 24.04
	"Apache/2.4.41 (Ubuntu)", // 20.04
	"Apache/2.4.57 (Ubuntu)",
	"Apache/2.4.29 (Ubuntu)", // 18.04
}

// NewDecoyProfile derives a stable, unique decoy identity from a seed (the auth token).
func NewDecoyProfile(seed string) DecoyProfile {
	h := sha256.Sum256([]byte("hedioum-decoy\x00" + seed))
	ver := apacheVersions[int(h[0])%len(apacheVersions)]
	daysAgo := int(binary.BigEndian.Uint16(h[1:3]))%700 + 30 // 30..730 days
	secs := int(binary.BigEndian.Uint16(h[3:5])) % 86400
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	lm := base.Add(-time.Duration(daysAgo)*24*time.Hour - time.Duration(secs)*time.Second)
	return DecoyProfile{
		apacheServer: ver,
		lastModified: lm.UTC().Format(http.TimeFormat), // "... GMT" (not "UTC")
		etagSuffix:   fmt.Sprintf("%x", binary.BigEndian.Uint64(h[8:16])),
	}
}

// defaultDecoyProfile backs the package-level ServeWebDecoy fallback (used only when
// no seeded profile is wired, e.g. the TLS mimic's built-in default and in tests).
var defaultDecoyProfile = NewDecoyProfile("")

// writeStatic emits the full header set a real web server returns for a static file
// (Last-Modified / ETag / Accept-Ranges), so the response shape is not itself a tell.
func (p DecoyProfile) writeStatic(conn net.Conn, server, contentType, extra, body string) {
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Read(make([]byte, 4096)) // consume (part of) the request line/headers
	etag := fmt.Sprintf("\"%x-%s\"", len(body), p.etagSuffix)
	resp := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nDate: %s\r\nServer: %s\r\nLast-Modified: %s\r\nETag: %s\r\n"+
			"Accept-Ranges: bytes\r\nContent-Length: %d\r\n%sContent-Type: %s\r\nConnection: close\r\n\r\n%s",
		time.Now().UTC().Format(http.TimeFormat), server, p.lastModified, etag, len(body), extra, contentType, body,
	)
	_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Write([]byte(resp))
}

// ServeApache answers with the Apache2 Ubuntu default page (per-install Server/date/ETag).
func (p DecoyProfile) ServeApache(conn net.Conn) {
	p.writeStatic(conn, p.apacheServer, "text/html; charset=UTF-8", "", apacheDefaultPage)
}

// ServeDirectAdminWeb answers with the exact page a DirectAdmin box serves on its web
// ports. Server stays "Apache/2" (shared by all real DA installs — blending in), with
// per-install date/ETag.
func (p DecoyProfile) ServeDirectAdminWeb(conn net.Conn) {
	p.writeStatic(conn, "Apache/2", "text/html", "Vary: User-Agent\r\n", daWebDefault)
}

// WebDecoyFor returns this profile's raw (net.Conn) web decoy for a persona style.
func (p DecoyProfile) WebDecoyFor(style string) func(net.Conn) {
	if style == "directadmin" {
		return p.ServeDirectAdminWeb
	}
	return p.ServeApache
}

// ServeWebDecoy is the package-level Apache fallback (default profile), used by the
// TLS mimic when no seeded decoy is configured.
func ServeWebDecoy(conn net.Conn) { defaultDecoyProfile.ServeApache(conn) }
