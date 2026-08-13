package mimic

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// DirectAdmin persona decoy for the :2222 panel. A probe or browser that reaches
// :2222 (but does not present the tunnel token) is served a faithful reproduction
// of the DirectAdmin "Evolution" login — the real logos, branded backgrounds and
// favicon, class names, layout, light/dark mode, and the exact response headers a
// live panel returns — so the box reads as an ordinary DirectAdmin server to both
// scanners and humans.
//
// It is display-only camouflage: it never validates, stores, or forwards any
// submitted credentials. A login attempt shows the real panel's error text; the
// page's script does not transmit the typed values.
//
// Behaviour mirrored from a live panel:
//   - GET /                       -> 302 to /evo/
//   - GET /evo/ , /evo/login, ... -> the login page (200, no-cache)
//   - GET /evo/assets/...         -> the embedded logos/backgrounds/favicon
//   - /api/*                      -> DirectAdmin-shaped JSON (401 for auth)
//
// For pixel-perfect interactive fidelity an operator can instead point the mimic's
// Decoy backend at a real DirectAdmin instance.

// daLoginPage is the rendered Evolution login, reproduced to match a real panel in
// both light and dark mode (follows the OS theme, with a working manual toggle).
// __HOST__/__DATETIME__ are filled per request.
const daLoginPage = `<!DOCTYPE html>
<html class="vue-app" lang="en">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8;" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>__HOST__ | Login</title>
        <link id="favicon" rel="shortcut icon" href="/evo/assets/favicon.CDLA4ANV.png" />
        <style>
            :root {
                --bg: #eaf1f7;
                --bg-img: url("/evo/assets/background.Cx34YJbp.svg");
                --logo: url("/evo/assets/logo.fe968txS.svg");
                --card: #ffffff;
                --card-shadow: 0 12px 40px rgba(15, 40, 70, .18);
                --label: #34383c;
                --input-bg: #ffffff;
                --input-border: #e2e6ea;
                --input-text: #1f2937;
                --placeholder: #9aa3af;
                --btn: #2c8ec4;
                --btn-hover: #2680b3;
                --dt: rgba(255, 255, 255, .92);
                --tool: #ffffff;
            }
            @media (prefers-color-scheme: dark) {
                :root:not([data-theme="light"]) {
                    --bg: #12151b;
                    --bg-img: url("/evo/assets/background-dark.BawLIQ0N.svg");
                    --logo: url("/evo/assets/logo2.AfEZecTW.svg");
                    --card: #242a35;
                    --card-shadow: 0 12px 40px rgba(0, 0, 0, .45);
                    --label: #c7cdd6;
                    --input-bg: #2d333f;
                    --input-border: #39404d;
                    --input-text: #e6e9ee;
                    --placeholder: #7d8797;
                    --btn-hover: #3399cf;
                    --dt: rgba(255, 255, 255, .8);
                    --tool: #e6e9ee;
                }
            }
            :root[data-theme="dark"] {
                --bg: #12151b;
                --bg-img: url("/evo/assets/background-dark.BawLIQ0N.svg");
                --logo: url("/evo/assets/logo2.AfEZecTW.svg");
                --card: #242a35;
                --card-shadow: 0 12px 40px rgba(0, 0, 0, .45);
                --label: #c7cdd6;
                --input-bg: #2d333f;
                --input-border: #39404d;
                --input-text: #e6e9ee;
                --placeholder: #7d8797;
                --btn-hover: #3399cf;
                --dt: rgba(255, 255, 255, .8);
                --tool: #e6e9ee;
            }
            * { box-sizing: border-box; }
            html, body { margin: 0; padding: 0; height: 100%; }
            body {
                min-height: 100vh;
                font-family: "Montserrat", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
                background-color: var(--bg);
                background-image: var(--bg-img);
                background-size: cover; background-position: center; background-repeat: no-repeat;
                display: flex; align-items: center; justify-content: center;
            }
            input::placeholder { color: var(--placeholder); }
            .Overlay { display: flex; align-items: center; justify-content: center; }
            .Wrapper { width: 380px; max-width: 92vw; }
            .Login.Box { background: var(--card); border-radius: 20px; box-shadow: var(--card-shadow); padding: 40px 40px 34px; }
            .Box__Header { height: 58px; margin: 0 auto 26px; background-image: var(--logo); background-size: contain; background-repeat: no-repeat; background-position: center; }
            .Box__Form { display: flex; flex-direction: column; }
            .InputLabel { color: var(--label); font-size: 15px; font-weight: 700; margin: 0 0 7px; }
            .Box__Form label:not(:first-child) { margin-top: 18px; }
            .Input { position: relative; margin: 0; }
            .Input__Text, .InputPassword__Input {
                width: 100%; height: 46px; border: 1px solid var(--input-border); border-radius: 9px;
                padding: 12px 15px; font-size: 15px; color: var(--input-text); background: var(--input-bg);
                font-family: inherit; outline: none;
            }
            .Input__Text:focus, .InputPassword__Input:focus { border-color: var(--btn); }
            .Input__Icon { position: absolute; top: 0; right: 14px; height: 46px; display: flex; align-items: center; color: var(--placeholder); cursor: pointer; }
            .Input__Icon svg { width: 20px; height: 20px; }
            .LoginError { color: #e0564f; font-size: 13.5px; line-height: 1.35; margin: 14px 0 0; min-height: 16px; }
            .Button { margin: 24px 0 0; height: 48px; width: 100%; border: 0; border-radius: 9px; background: var(--btn); color: #fff; font-size: 16px; font-weight: 600; font-family: inherit; cursor: pointer; }
            .Button:hover { background: var(--btn-hover); }
            .DateTimeBlock { color: var(--dt); font-size: 13px; text-align: center; margin: 16px 0 0; text-shadow: 0 1px 2px rgba(0, 0, 0, .25); }
            .Toolbar { position: fixed; top: 14px; right: 24px; display: flex; align-items: center; gap: 18px; color: var(--tool); }
            .ModeToggle { display: flex; align-items: center; gap: 4px; }
            .ModeToggle .icon { width: 34px; height: 34px; display: flex; align-items: center; justify-content: center; border-radius: 50%; cursor: pointer; opacity: .85; color: var(--tool); }
            .ModeToggle .icon svg { width: 20px; height: 20px; }
            .ModeToggle .icon.--active { background: var(--btn); color: #fff; opacity: 1; }
            .LanguageDropdown .LD__Button { display: flex; align-items: center; gap: 8px; font-size: 14px; cursor: pointer; color: var(--tool); }
        </style>
    </head>
    <body>
        <div id="root" data-v-app>
            <div id="EvoLoginApp">
                <div class="Toolbar">
                    <div class="ModeToggle">
                        <span class="icon" data-mode="light" title="Light Mode"><svg viewBox="0 0 24 24"><path fill="currentColor" d="M12 7a5 5 0 1 0 0 10 5 5 0 0 0 0-10zm0 8a3 3 0 1 1 0-6 3 3 0 0 1 0 6zm0-11a1 1 0 0 1 1 1v1a1 1 0 1 1-2 0V5a1 1 0 0 1 1-1zm0 14a1 1 0 0 1 1 1v1a1 1 0 1 1-2 0v-1a1 1 0 0 1 1-1zM5 11a1 1 0 1 1 0 2H4a1 1 0 1 1 0-2h1zm15 0a1 1 0 1 1 0 2h-1a1 1 0 1 1 0-2h1zM6.34 5.34l.7.7A1 1 0 1 1 5.64 7.46l-.71-.71a1 1 0 0 1 1.41-1.41zm12.02 12.02l.7.7a1 1 0 0 1-1.41 1.42l-.71-.71a1 1 0 0 1 1.42-1.41zM6.34 18.66a1 1 0 0 1-1.41-1.41l.71-.71a1 1 0 1 1 1.41 1.42l-.71.7zM18.36 6.34a1 1 0 0 1-1.42-1.41l.71-.71a1 1 0 0 1 1.42 1.41l-.71.71z"/></svg></span>
                        <span class="icon --active" data-mode="system" title="Follow system mode"><svg viewBox="0 0 24 24"><path fill="currentColor" d="M4 5a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-5v2h3a1 1 0 1 1 0 2H8a1 1 0 1 1 0-2h3v-2H6a2 2 0 0 1-2-2V5zm2 0v9h12V5H6z"/></svg></span>
                        <span class="icon" data-mode="dark" title="Dark Mode"><svg viewBox="0 0 24 24"><path fill="currentColor" d="M12.74 2.02a1 1 0 0 0-1.1 1.36A7 7 0 0 0 20.62 12.36a1 1 0 0 0 .36-1.1A9 9 0 1 1 12.74 2.02zM12 20a7 7 0 0 1-1.9-13.74A9 9 0 0 0 17.74 13.9 7 7 0 0 1 12 20z"/></svg></span>
                    </div>
                    <div class="LanguageDropdown"><div class="LD__Button"><svg viewBox="0 0 24 24" width="22" height="22" fill="none"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.6"/><path opacity=".75" d="M22 12H2M19.76 18.2C17.17 17.4 14.59 17 12 17s-5.22.41-7.83 1.23M19.76 5.8C17.17 6.6 14.59 7 12 7 9.39 7 6.78 6.59 4.17 5.77" stroke="currentColor" stroke-width="1.6"/><path opacity=".75" d="M11.3 2s-4 4.46-4 10 4 10 4 10M12.26 2s4 4.46 4 10-4 10-4 10" stroke="currentColor" stroke-width="1.6"/></svg><span class="LD_Text">English</span></div></div>
                </div>
                <section class="Overlay">
                    <div class="Wrapper">
                        <div class="Login Box --logged-out">
                            <div class="Box__Header"></div>
                            <form id="LoginForm" class="Box__Form" autocomplete="on">
                                <label class="InputLabel" for="username">Username</label>
                                <div class="Input">
                                    <input id="username" name="username" class="Input__Text" type="text" placeholder="Please enter username" autocomplete="username" />
                                </div>
                                <label class="InputLabel" for="password">Password</label>
                                <div class="Input InputPassword">
                                    <input id="password" name="password" class="InputPassword__Input" type="password" placeholder="Please enter your password" autocomplete="current-password" />
                                    <a class="Input__Icon hoverable" role="button" aria-label="Show password"><svg viewBox="0 0 48 48"><path fill="currentColor" d="M24 8C11.056 8 0 24 0 24s11.048 16 24 16c12.944 0 24-16 24-16S36.952 8 24 8zm0 28c-7.469 0-15.137-7.324-19-12 3.853-4.678 11.502-12 19-12 7.469 0 15.137 7.324 19 12-3.853 4.678-11.502 12-19 12zm0-20a8 8 0 1 0 0 16 8 8 0 0 0 0-16zm0 12c-2.451 0-4-1.549-4-4s1.549-4 4-4 4 1.549 4 4-1.549 4-4 4z"/></svg></a>
                                </div>
                                <div class="LoginError" id="loginError"></div>
                                <button class="Button" type="submit"><span>Sign in</span></button>
                            </form>
                        </div>
                        <div class="DateTimeBlock">__DATETIME__</div>
                    </div>
                </section>
            </div>
        </div>
        <script>
            (function () {
                try {
                    var root = document.documentElement;
                    var icons = document.querySelectorAll(".ModeToggle .icon");
                    icons.forEach(function (ic) {
                        ic.addEventListener("click", function () {
                            icons.forEach(function (x) { x.classList.remove("--active"); });
                            ic.classList.add("--active");
                            var m = ic.getAttribute("data-mode");
                            if (m === "system") { root.removeAttribute("data-theme"); }
                            else { root.setAttribute("data-theme", m); }
                        });
                    });
                    var eye = document.querySelector(".Input__Icon");
                    var pw = document.getElementById("password");
                    if (eye && pw) { eye.addEventListener("click", function () { pw.type = pw.type === "password" ? "text" : "password"; }); }
                    var f = document.getElementById("LoginForm");
                    var err = document.getElementById("loginError");
                    if (f) {
                        f.addEventListener("submit", function (e) {
                            e.preventDefault();
                            // Credentials are never transmitted or stored; only the panel's
                            // failed-login state is mimicked.
                            try { fetch("/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }); } catch (_) {}
                            err.textContent = "Hmm, login details do not seem to be correct. Please try again.";
                        });
                    }
                } catch (_) {}
            })();
        </script>
    </body>
</html>
`

// ServeDirectAdminPanel handles one (keep-alive) HTTP/1.1 connection as a
// DirectAdmin Evolution panel would.
func ServeDirectAdminPanel(conn net.Conn) {
	br := bufio.NewReader(conn)
	for i := 0; i < 64; i++ { // bound the keep-alive loop (a browser fetches several assets)
		_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if req.Body != nil {
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
		}
		keepAlive := req.ProtoAtLeast(1, 1) && !req.Close
		_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if err := routeDA(conn, req, keepAlive); err != nil {
			return
		}
		if !keepAlive {
			return
		}
	}
}

// daAssetRoutes maps the panel's asset paths to embedded files + content types.
var daAssetRoutes = map[string]struct{ file, ct string }{
	"/evo/assets/logo.fe968txS.svg":            {"logo.fe968txS.svg", "image/svg+xml"},
	"/evo/assets/logo2.AfEZecTW.svg":           {"logo2.AfEZecTW.svg", "image/svg+xml"},
	"/evo/assets/background.Cx34YJbp.svg":      {"background.Cx34YJbp.svg", "image/svg+xml"},
	"/evo/assets/background-dark.BawLIQ0N.svg": {"background-dark.BawLIQ0N.svg", "image/svg+xml"},
	"/evo/assets/favicon.CDLA4ANV.png":         {"favicon.CDLA4ANV.png", "image/png"},
	"/favicon.ico":                             {"favicon.CDLA4ANV.png", "image/png"},
}

func routeDA(w net.Conn, req *http.Request, keepAlive bool) error {
	path := req.URL.Path
	if a, ok := daAssetRoutes[path]; ok {
		return writeDAAsset(w, a.file, a.ct, keepAlive)
	}
	switch {
	case path == "/":
		return writeDARedirect(w, "/evo/", keepAlive)
	case path == "/api/info":
		host, _ := os.Hostname()
		body := fmt.Sprintf(`{"hostname":%q,"allowPasswordReset":false,"OTPTrustDays":30,"languages":[],"license":{"active":true}}`, host)
		return writeDA(w, 200, "application/json", body, keepAlive)
	case path == "/api/session/state":
		return writeDA(w, 401, "application/json", `{"error":"Unauthenticated"}`, keepAlive)
	case strings.HasPrefix(path, "/api/login"):
		// A login attempt with unknown credentials — answered exactly as the real
		// panel answers a bad login. No credential is inspected or stored.
		return writeDA(w, 401, "application/json", `{"error":"Cannot Log In","result":"Invalid credentials"}`, keepAlive)
	case strings.HasPrefix(path, "/api/"):
		return writeDA(w, 401, "application/json", `{"error":"Unauthenticated"}`, keepAlive)
	default:
		// The login page for /evo/, /evo/login and every SPA route.
		return writeDA(w, 200, "text/html; charset=utf-8", daLoginHTML(), keepAlive)
	}
}

// daLoginHTML fills the per-request fields (hostname, local time in the panel's format).
func daLoginHTML() string {
	host, _ := os.Hostname()
	if host == "" {
		host = "server"
	}
	page := strings.ReplaceAll(daLoginPage, "__HOST__", host)
	page = strings.ReplaceAll(page, "__DATETIME__", time.Now().Format("1/2/2006, 3:04 PM"))
	return page
}

// writeDA writes an HTTP/1.1 response carrying DirectAdmin's characteristic headers:
// no Server header, plus X-Frame-Options / X-Content-Type-Options / Cache-Control.
func writeDA(w io.Writer, status int, contentType, body string, keepAlive bool) error {
	conn := "close"
	if keepAlive {
		conn = "keep-alive"
	}
	statusText := map[int]string{200: "OK", 401: "Unauthorized", 404: "Not Found"}[status]
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nDate: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n"+
		"Cache-Control: no-cache\r\nX-Frame-Options: sameorigin\r\nX-Content-Type-Options: nosniff\r\n"+
		"Vary: Origin\r\nConnection: %s\r\n\r\n%s",
		status, statusText, time.Now().UTC().Format(time.RFC1123), contentType, len(body), conn, body)
	_, err := w.Write([]byte(resp))
	return err
}

// writeDARedirect emits the 302 a real panel returns for "/".
func writeDARedirect(w io.Writer, location string, keepAlive bool) error {
	body := fmt.Sprintf("<a href=\"%s\">Found</a>.\n", location)
	conn := "close"
	if keepAlive {
		conn = "keep-alive"
	}
	resp := fmt.Sprintf("HTTP/1.1 302 Found\r\nDate: %s\r\nLocation: %s\r\nContent-Type: text/html; charset=utf-8\r\n"+
		"Content-Length: %d\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: sameorigin\r\nConnection: %s\r\n\r\n%s",
		time.Now().UTC().Format(time.RFC1123), location, len(body), conn, body)
	_, err := w.Write([]byte(resp))
	return err
}

// writeDAAsset serves one embedded Evolution asset with an immutable cache header.
func writeDAAsset(w io.Writer, name, contentType string, keepAlive bool) error {
	b, err := daAssets.ReadFile("daassets/" + name)
	if err != nil {
		return writeDA(w, 404, "text/html; charset=utf-8", "Not Found", keepAlive)
	}
	conn := "close"
	if keepAlive {
		conn = "keep-alive"
	}
	hdr := fmt.Sprintf("HTTP/1.1 200 OK\r\nDate: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n"+
		"Cache-Control: public, max-age=31536000, immutable\r\nX-Content-Type-Options: nosniff\r\nConnection: %s\r\n\r\n",
		time.Now().UTC().Format(time.RFC1123), contentType, len(b), conn)
	if _, err := w.Write([]byte(hdr)); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}
