package webui

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/mahdi-byte64/arange-tun/internal/manage"
)

// External-tunnel endpoints: create, list, get, update, delete and restart for
// frp and backhaul tunnels. Like the built-in tunnel endpoints they sit behind
// requireAuth and are thin wrappers over the manage functions, which install
// the third-party binary, generate its config and run it under systemd.

// handleExtCreate builds a new external (frp/backhaul) tunnel and starts it.
func (s *server) handleExtCreate(w http.ResponseWriter, r *http.Request) {
	t, ok := s.decodeExt(w, r)
	if !ok {
		return
	}
	if err := manage.CreateExtTunnel(t); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"status": "ok", "name": t.Name})
}

// handleExtUpdate rewrites an existing external tunnel and restarts it.
func (s *server) handleExtUpdate(w http.ResponseWriter, r *http.Request) {
	t, ok := s.decodeExt(w, r)
	if !ok {
		return
	}
	if err := manage.UpdateExtTunnel(t); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"status": "ok", "name": t.Name})
}

// decodeExt reads and size-limits the JSON body shared by create and update.
func (s *server) decodeExt(w http.ResponseWriter, r *http.Request) (manage.ExtTunnel, bool) {
	var t manage.ExtTunnel
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return t, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTunnelBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		http.Error(w, "could not read the request: "+err.Error(), http.StatusBadRequest)
		return t, false
	}
	return t, true
}

// handleExtList returns every external tunnel with its live state.
func (s *server) handleExtList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, manage.ListExtTunnels())
}

// handleExtGet returns one external tunnel's stored config for editing.
func (s *server) handleExtGet(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "missing tunnel name", http.StatusBadRequest)
		return
	}
	t, err := manage.GetExtTunnel(name)
	if err != nil {
		http.Error(w, "no external tunnel named "+name, http.StatusNotFound)
		return
	}
	writeJSON(w, t)
}

// handleExtDelete stops and removes an external tunnel.
func (s *server) handleExtDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := decodeTunnelName(r)
	if name == "" {
		http.Error(w, "missing tunnel name", http.StatusBadRequest)
		return
	}
	if !manage.ExtExists(name) {
		http.Error(w, "no external tunnel named "+name, http.StatusNotFound)
		return
	}
	if err := manage.DeleteExtTunnel(name); err != nil {
		http.Error(w, "could not delete the tunnel: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

// handleExtRestart restarts an external tunnel's service.
func (s *server) handleExtRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := decodeTunnelName(r)
	if name == "" {
		http.Error(w, "missing tunnel name", http.StatusBadRequest)
		return
	}
	if !manage.ExtExists(name) {
		http.Error(w, "no external tunnel named "+name, http.StatusNotFound)
		return
	}
	if err := manage.RestartExtTunnel(name); err != nil {
		http.Error(w, "could not restart the tunnel: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}
