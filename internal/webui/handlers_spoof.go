package webui

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/mahdi-byte64/arange-tun/internal/manage"
)

// Spoof has its own dedicated panel (a UDP pipe over forged-source-IP packets),
// so it gets its own endpoints: create/edit each role, list, and the two helper
// operations — the spoof tester and the IP-list scanner.

func (s *server) handleSpoofClientCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTunnelBody)
	var req struct {
		Edit        bool   `json:"edit"`
		Name        string `json:"name"`
		Key         string `json:"key"`
		Transport   string `json:"transport"`
		SpoofIP     string `json:"spoofIP"`
		PeerSpoofIP string `json:"peerSpoofIP"`
		Listen      string `json:"listen"`
		ServerIP    string `json:"serverIP"`
		ServerPort  int    `json:"serverPort"`
		RecvPort    int    `json:"recvPort"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "could not read the request: "+err.Error(), http.StatusBadRequest)
		return
	}
	cr := manage.SpoofClientReq{
		Name: req.Name, Key: req.Key, Transport: req.Transport,
		SpoofIP: req.SpoofIP, PeerSpoofIP: req.PeerSpoofIP,
		Listen: req.Listen, ServerIP: req.ServerIP, ServerPort: req.ServerPort, RecvPort: req.RecvPort,
	}
	var key string
	var err error
	if req.Edit {
		key, err = manage.UpdateSpoofClient(cr)
	} else {
		key, err = manage.CreateSpoofClient(cr)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"status": "ok", "name": strings.TrimSpace(req.Name), "key": key})
}

func (s *server) handleSpoofServerCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTunnelBody)
	var req struct {
		Edit        bool   `json:"edit"`
		Name        string `json:"name"`
		Key         string `json:"key"`
		Transport   string `json:"transport"`
		SpoofIP     string `json:"spoofIP"`
		PeerSpoofIP string `json:"peerSpoofIP"`
		ListenPort  int    `json:"listenPort"`
		Forward     string `json:"forward"`
		ClientIP    string `json:"clientIP"`
		ClientPort  int    `json:"clientPort"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "could not read the request: "+err.Error(), http.StatusBadRequest)
		return
	}
	sr := manage.SpoofServerReq{
		Name: req.Name, Key: req.Key, Transport: req.Transport,
		SpoofIP: req.SpoofIP, PeerSpoofIP: req.PeerSpoofIP,
		ListenPort: req.ListenPort, Forward: req.Forward, ClientIP: req.ClientIP, ClientPort: req.ClientPort,
	}
	var key string
	var err error
	if req.Edit {
		key, err = manage.UpdateSpoofServer(sr)
	} else {
		key, err = manage.CreateSpoofServer(sr)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"status": "ok", "name": strings.TrimSpace(req.Name), "key": key})
}

func (s *server) handleSpoofGet(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "missing tunnel name", http.StatusBadRequest)
		return
	}
	view, err := manage.SpoofForEdit(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, view)
}

// handleSpoofList returns just the spoof tunnels with their live state, for the
// dedicated panel.
func (s *server) handleSpoofList(w http.ResponseWriter, r *http.Request) {
	health := manage.AllHealth()
	type row struct {
		Name  string `json:"name"`
		Role  string `json:"role"`
		Addr  string `json:"addr"`
		State string `json:"state"`
	}
	var out []row
	for _, t := range manage.SpoofList() {
		out = append(out, row{Name: t.Name, Role: t.Role, Addr: t.Addr, State: health[t.Name].State})
	}
	writeJSON(w, out)
}

// handleSpoofScan expands a single/range/CIDR spec into concrete IPs.
func (s *server) handleSpoofScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Spec string `json:"spec"`
		Max  int    `json:"max"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "could not read the request: "+err.Error(), http.StatusBadRequest)
		return
	}
	ips, err := manage.SpoofExpandIPs(req.Spec, req.Max)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ips": ips, "count": len(ips)})
}

// handleSpoofTestReceive listens for probe packets for a window and returns the
// per-IP delivery counts. Run it on the peer, then send from the other box.
func (s *server) handleSpoofTestReceive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Port      int    `json:"port"`
		Transport string `json:"transport"`
		Seconds   int    `json:"seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "could not read the request: "+err.Error(), http.StatusBadRequest)
		return
	}
	counts, err := manage.SpoofReceive(req.Port, req.Transport, req.Seconds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"counts": counts})
}

// handleSpoofTestSend forges probes from each candidate IP (single/range/CIDR)
// toward the peer's real IP:port.
func (s *server) handleSpoofTestSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PeerIP    string `json:"peerIP"`
		Port      int    `json:"port"`
		Transport string `json:"transport"`
		Spec      string `json:"spec"`
		Count     int    `json:"count"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "could not read the request: "+err.Error(), http.StatusBadRequest)
		return
	}
	ips, err := manage.SpoofExpandIPs(req.Spec, 4096)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := manage.SpoofSend(req.PeerIP, req.Port, req.Transport, ips, req.Count); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"status": "ok", "sentIPs": len(ips)})
}
