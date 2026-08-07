package webui

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/mahdi-byte64/arange-tun/internal/app"
	"github.com/mahdi-byte64/arange-tun/internal/manage"
)

// Tunnel lifecycle endpoints: create, delete and restart. These are the first
// mutating actions in the panel that are not panel-scoped — until now tunnels
// were built and managed only from the CLI. They sit behind requireAuth, so a
// read-only viewer cannot reach them, and each one is a thin wrapper over the
// same manage functions the CLI menu calls.

// maxTunnelBody caps a create request. A tunnel description is a few kilobytes
// at most; anything larger is a mistake or an attack.
const maxTunnelBody = 64 << 10 // 64 KiB

// handleTunnelCreate builds a new tunnel from a JSON request and starts it.
// This is the web equivalent of the CLI's "Setup Server" / "Setup Client"
// flows: the request is validated, a config and systemd unit are written, and
// the service is started — all through manage.CreateTunnel so both paths behave
// identically.
func (s *server) handleTunnelCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTunnelBody)

	var req manage.TunnelRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "could not read the request: "+err.Error(), http.StatusBadRequest)
		return
	}

	res, err := manage.CreateTunnel(req)
	if err != nil {
		// Every error manage.CreateTunnel returns before touching the disk is a
		// validation problem the user can fix, so report it as a 400 with the
		// message shown verbatim.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{
		"status":  "ok",
		"name":    res.Name,
		"service": res.Service,
		"active":  res.Active,
		"token":   res.Token,
	})
}

// handleTunnelGet returns an existing tunnel's config in the same shape the
// create form uses, so the panel can prefill it for editing.
func (s *server) handleTunnelGet(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "missing tunnel name", http.StatusBadRequest)
		return
	}
	if _, ok := manage.Find(name); !ok {
		http.Error(w, "no tunnel named "+name, http.StatusNotFound)
		return
	}
	req, err := manage.TunnelForEdit(name)
	if err != nil {
		http.Error(w, "could not read the tunnel: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, req)
}

// handleTunnelUpdate rewrites an existing tunnel from an edited request and
// restarts it — the web equivalent of the CLI's Edit flow, so a change no longer
// means delete-and-recreate.
func (s *server) handleTunnelUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTunnelBody)

	var req manage.TunnelRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "could not read the request: "+err.Error(), http.StatusBadRequest)
		return
	}

	res, err := manage.UpdateTunnel(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{
		"status":  "ok",
		"name":    res.Name,
		"service": res.Service,
		"active":  res.Active,
		"token":   res.Token,
	})
}

// tunnelNameRequest is the body shared by the delete and restart endpoints.
type tunnelNameRequest struct {
	Name string `json:"name"`
}

// handleTunnelDelete stops, disables and removes a tunnel and its config.
func (s *server) handleTunnelDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := decodeTunnelName(r)
	if name == "" {
		http.Error(w, "missing tunnel name", http.StatusBadRequest)
		return
	}
	if _, ok := manage.Find(name); !ok {
		http.Error(w, "no tunnel named "+name, http.StatusNotFound)
		return
	}
	if err := manage.Delete(name); err != nil {
		http.Error(w, "could not delete the tunnel: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

// handleTunnelRestart restarts a tunnel's systemd service.
func (s *server) handleTunnelRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := decodeTunnelName(r)
	if name == "" {
		http.Error(w, "missing tunnel name", http.StatusBadRequest)
		return
	}
	if _, ok := manage.Find(name); !ok {
		http.Error(w, "no tunnel named "+name, http.StatusNotFound)
		return
	}
	if err := manage.RestartService(app.ServiceName(name)); err != nil {
		http.Error(w, "could not restart the tunnel: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

// decodeTunnelName pulls the tunnel name from a JSON body, falling back to a
// form value when the body is not JSON. It caps the body first: a name is tiny,
// so a large body is never legitimate here.
func decodeTunnelName(r *http.Request) string {
	r.Body = http.MaxBytesReader(nil, r.Body, maxTunnelBody)
	var req tunnelNameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
		if n := strings.TrimSpace(req.Name); n != "" {
			return n
		}
	}
	return strings.TrimSpace(r.FormValue("name"))
}
