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

// handleWGServerCreate generates a WireGuard exit-node tunnel and returns the
// client config to hand out.
func (s *server) handleWGServerCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTunnelBody)
	var req struct {
		Name       string `json:"name"`
		ListenPort int    `json:"listenPort"`
		Endpoint   string `json:"endpoint"`
		DNS        string `json:"dns"`
		Egress     string `json:"egress"`
		Edit       bool   `json:"edit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "could not read the request: "+err.Error(), http.StatusBadRequest)
		return
	}
	// An edit preserves the server's keys and peers, so it does not hand back a
	// new client config — the existing one still works (only its Endpoint port
	// changes if the listen port did).
	if req.Edit {
		if err := manage.UpdateWireGuardServer(req.Name, req.ListenPort, req.Egress); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"status": "ok", "name": strings.TrimSpace(req.Name), "edit": true})
		return
	}
	conf, err := manage.CreateWireGuardServer(req.Name, req.ListenPort, req.Endpoint, req.DNS, req.Egress)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"status": "ok", "name": strings.TrimSpace(req.Name), "clientConfig": conf})
}

// handleWGGet returns a WireGuard tunnel's editable fields for the panel's edit
// form.
func (s *server) handleWGGet(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "missing tunnel name", http.StatusBadRequest)
		return
	}
	view, err := manage.WireGuardForEdit(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, view)
}

// handleWGClientCreate brings up a userspace WireGuard client from a pasted
// config and exposes a SOCKS5 proxy.
func (s *server) handleWGClientCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTunnelBody)
	var req struct {
		Name      string `json:"name"`
		Config    string `json:"config"`
		SocksBind string `json:"socksBind"`
		SocksPort int    `json:"socksPort"`
		Edit      bool   `json:"edit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "could not read the request: "+err.Error(), http.StatusBadRequest)
		return
	}
	var err error
	if req.Edit {
		// An empty config on an edit keeps the current one (SOCKS-only change).
		err = manage.UpdateWireGuardClient(req.Name, req.Config, req.SocksBind, req.SocksPort)
	} else {
		err = manage.CreateWireGuardClient(req.Name, req.Config, req.SocksBind, req.SocksPort)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"status": "ok", "name": strings.TrimSpace(req.Name)})
}

// handleSSHClientCreate starts an SSH egress client (or edits one) that dials an
// SSH server and exposes a local SOCKS5.
func (s *server) handleSSHClientCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTunnelBody)
	var req struct {
		Name      string `json:"name"`
		Host      string `json:"host"`
		Port      int    `json:"port"`
		User      string `json:"user"`
		Password  string `json:"password"`
		SocksPort int    `json:"socksPort"`
		Edit      bool   `json:"edit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "could not read the request: "+err.Error(), http.StatusBadRequest)
		return
	}
	var err error
	if req.Edit {
		err = manage.UpdateSSHClient(req.Name, req.Host, req.Port, req.User, req.Password, "127.0.0.1", req.SocksPort)
	} else {
		err = manage.CreateSSHClient(req.Name, req.Host, req.Port, req.User, req.Password, "127.0.0.1", req.SocksPort)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"status": "ok", "name": strings.TrimSpace(req.Name)})
}

// handleSSHGet returns an SSH tunnel's config so the panel can prefill its edit
// form. The password is not returned — an empty password on save keeps it.
func (s *server) handleSSHGet(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "missing tunnel name", http.StatusBadRequest)
		return
	}
	view, err := manage.SSHForEdit(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	view.Password = "" // never send the password back to the browser
	writeJSON(w, view)
}

// handlePacketServerCreate starts a Packet exit node (abroad) and returns the
// shared key the client must be given.
func (s *server) handlePacketServerCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTunnelBody)
	var req struct {
		Name       string `json:"name"`
		ListenPort int    `json:"listenPort"`
		Key        string `json:"key"`
		Block      string `json:"block"`
		Edit       bool   `json:"edit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "could not read the request: "+err.Error(), http.StatusBadRequest)
		return
	}
	var key string
	var err error
	if req.Edit {
		key, err = manage.UpdatePacketServer(req.Name, req.ListenPort, req.Key, req.Block)
	} else {
		key, err = manage.CreatePacketServer(req.Name, req.ListenPort, req.Key, req.Block)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"status": "ok", "name": strings.TrimSpace(req.Name), "key": key, "edit": req.Edit})
}

// handlePacketGet returns a packet tunnel's config so the panel can prefill its
// edit form.
func (s *server) handlePacketGet(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "missing tunnel name", http.StatusBadRequest)
		return
	}
	view, err := manage.PacketForEdit(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, view)
}

// handlePacketClientCreate starts a Packet entry node (Iran) that exposes ports
// and dials the abroad server.
func (s *server) handlePacketClientCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTunnelBody)
	var req struct {
		Name       string   `json:"name"`
		ServerAddr string   `json:"serverAddr"`
		Key        string   `json:"key"`
		Block      string   `json:"block"`
		Ports      []string `json:"ports"`
		Socks      string   `json:"socks"`
		Edit       bool     `json:"edit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "could not read the request: "+err.Error(), http.StatusBadRequest)
		return
	}
	var err error
	if req.Edit {
		err = manage.UpdatePacketClient(req.Name, req.ServerAddr, req.Key, req.Block, req.Ports, req.Socks)
	} else {
		err = manage.CreatePacketClient(req.Name, req.ServerAddr, req.Key, req.Block, req.Ports, req.Socks)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"status": "ok", "name": strings.TrimSpace(req.Name)})
}

// handleHedioumForeignCreate starts a Hedioum exit node (abroad) and returns the
// shared token the iran hub must be given.
func (s *server) handleHedioumForeignCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTunnelBody)
	var req struct {
		Name         string `json:"name"`
		ListenPort   int    `json:"listenPort"`
		AuthToken    string `json:"authToken"`
		Mimic        string `json:"mimic"`
		EgressIPMode string `json:"egressIPMode"`
		Domain       string `json:"domain"`
		ACMEEmail    string `json:"acmeEmail"`
		DecoyStyle   string `json:"decoyStyle"`
		Edit         bool   `json:"edit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "could not read the request: "+err.Error(), http.StatusBadRequest)
		return
	}
	var token string
	var err error
	if req.Edit {
		token, err = manage.UpdateHedioumForeign(req.Name, req.ListenPort, req.AuthToken, req.Mimic, req.EgressIPMode, req.Domain, req.ACMEEmail, req.DecoyStyle)
	} else {
		token, err = manage.CreateHedioumForeign(req.Name, req.ListenPort, req.AuthToken, req.Mimic, req.EgressIPMode, req.Domain, req.ACMEEmail, req.DecoyStyle)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"status": "ok", "name": strings.TrimSpace(req.Name), "token": token, "edit": req.Edit})
}

// handleHedioumIranCreate starts a Hedioum entry hub (Iran) that exposes a local
// SOCKS5 and dials the abroad foreign node.
func (s *server) handleHedioumIranCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTunnelBody)
	var req struct {
		Name       string `json:"name"`
		ServerAddr string `json:"serverAddr"`
		ServerPort int    `json:"serverPort"`
		AuthToken  string `json:"authToken"`
		Mimic      string `json:"mimic"`
		SocksPort  int    `json:"socksPort"`
		Edit       bool   `json:"edit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "could not read the request: "+err.Error(), http.StatusBadRequest)
		return
	}
	var err error
	if req.Edit {
		err = manage.UpdateHedioumIran(req.Name, req.ServerAddr, req.ServerPort, req.AuthToken, req.Mimic, req.SocksPort)
	} else {
		err = manage.CreateHedioumIran(req.Name, req.ServerAddr, req.ServerPort, req.AuthToken, req.Mimic, req.SocksPort)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"status": "ok", "name": strings.TrimSpace(req.Name)})
}

// handleHedioumGet returns a hedioum tunnel's config so the panel can prefill its
// edit form.
func (s *server) handleHedioumGet(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "missing tunnel name", http.StatusBadRequest)
		return
	}
	view, err := manage.HedioumForEdit(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, view)
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

// handleTunnelStop stops a tunnel and disables it, so it stays down until it is
// started again (and does not come back on reboot). The config is left in place.
func (s *server) handleTunnelStop(w http.ResponseWriter, r *http.Request) {
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
	if err := manage.DisableService(app.ServiceName(name)); err != nil {
		http.Error(w, "could not stop the tunnel: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

// handleTunnelStart starts (and enables) a previously stopped tunnel.
func (s *server) handleTunnelStart(w http.ResponseWriter, r *http.Request) {
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
	if err := manage.StartService(app.ServiceName(name)); err != nil {
		http.Error(w, "could not start the tunnel: "+err.Error(), http.StatusInternalServerError)
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
